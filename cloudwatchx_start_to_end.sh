#!/usr/bin/env bash
# CloudWatchX — multi-region AWS inventory + CloudWatch-style dashboard
# Tested design target: Amazon Linux 2023, Docker, Python 3, Flask, Boto3.
# Uses the EC2 instance role / AWS default credential chain. Do NOT hard-code keys.

set -Eeuo pipefail

APP_DIR="${APP_DIR:-$HOME/cloudwatchx}"
CONTAINER_NAME="${CONTAINER_NAME:-cloudwatchx}"
IMAGE_NAME="${IMAGE_NAME:-cloudwatchx:latest}"
HOST_PORT="${HOST_PORT:-5000}"
CONTAINER_PORT="5000"

echo "=========================================================="
echo " CloudWatchX setup — all enabled AWS regions"
echo " App directory: $APP_DIR"
echo "=========================================================="

# Install Docker on Amazon Linux 2023 if needed.
if ! command -v docker >/dev/null 2>&1; then
  echo "[1/7] Installing Docker..."
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf update -y
    sudo dnf install -y docker python3
  else
    echo "ERROR: Docker is missing and this script only auto-installs it on dnf-based systems."
    exit 1
  fi
fi

sudo systemctl enable --now docker
if ! docker info >/dev/null 2>&1; then
  sudo usermod -aG docker "$USER" || true
  echo "Docker requires elevated access for this session; continuing with sudo docker."
  DOCKER="sudo docker"
else
  DOCKER="docker"
fi

# Preserve the previous project before recreating it.
if [[ -d "$APP_DIR" ]]; then
  BACKUP="${APP_DIR}.backup.$(date +%Y%m%d-%H%M%S)"
  echo "[2/7] Backing up existing project to $BACKUP"
  cp -a "$APP_DIR" "$BACKUP"
else
  echo "[2/7] No previous project folder found."
fi

mkdir -p "$APP_DIR/templates" "$APP_DIR/services"
cd "$APP_DIR"

cat > requirements.txt <<'REQ'
Flask>=3.0,<4.0
boto3>=1.34
gunicorn>=22.0
REQ

cat > app.py <<'PY'
import os
import time
import logging
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from flask import Flask, jsonify, render_template

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("cloudwatchx")

AWS_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=4,
    read_timeout=12,
)
SESSION = boto3.Session()
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "60"))
_cached_payload = None
_cached_at = 0.0

def aws_client(service, region=None):
    return SESSION.client(service, region_name=region, config=AWS_CONFIG)

def pages(client, operation, result_key, **kwargs):
    """Return a list using a boto3 paginator when available."""
    try:
        paginator = client.get_paginator(operation)
        output = []
        for page in paginator.paginate(**kwargs):
            output.extend(page.get(result_key, []) or [])
        return output
    except (ClientError, BotoCoreError, ValueError):
        # Some operations do not support pagination.
        response = getattr(client, operation)(**kwargs)
        return response.get(result_key, []) or []

def short_error(exc):
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "AWSClientError")
        message = err.get("Message", str(exc))
        return f"{code}: {message}"
    if isinstance(exc, NoCredentialsError):
        return "No AWS credentials found. Attach an IAM role to this EC2 instance."
    return str(exc)[:300]

def safe_call(service_name, region, fn):
    try:
        return fn(), None
    except Exception as exc:
        log.warning("%s in %s failed: %s", service_name, region or "global", short_error(exc))
        return [], short_error(exc)

def get_regions():
    # Discover regions from the account, including regions that are opted in.
    ec2 = aws_client("ec2", SESSION.region_name or "ap-south-1")
    response = ec2.describe_regions(AllRegions=True)
    regions = []
    for item in response.get("Regions", []):
        status = item.get("OptInStatus", "")
        if status in ("opted-in", "opt-in-not-required"):
            regions.append(item["RegionName"])
    return sorted(set(regions))

def collect_region(region):
    """Collect inventory for one region. Errors are isolated per service."""
    result = {
        "region": region,
        "ec2_instances": [], "vpcs": [], "subnets": [], "security_groups": [],
        "route_tables": [], "internet_gateways": [], "nat_gateways": [],
        "ebs_volumes": [], "auto_scaling_groups": [], "rds_instances": [],
        "lambda_functions": [], "load_balancers": [], "cloudwatch_alarms": [],
        "dynamodb_tables": [], "ecs_clusters": [], "eks_clusters": [],
        "service_errors": {}
    }
    ec2 = aws_client("ec2", region)

    def run(label, fn, target):
        value, error = safe_call(label, region, fn)
        result[target] = value
        if error:
            result["service_errors"][label] = error

    def instances():
        out = []
        reservations = pages(ec2, "describe_instances", "Reservations")
        for reservation in reservations:
            for item in reservation.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in item.get("Tags", [])}
                out.append({
                    "id": item.get("InstanceId"),
                    "name": tags.get("Name", "(no name)"),
                    "state": item.get("State", {}).get("Name", "unknown"),
                    "type": item.get("InstanceType", ""),
                    "az": item.get("Placement", {}).get("AvailabilityZone", ""),
                    "private_ip": item.get("PrivateIpAddress", ""),
                    "public_ip": item.get("PublicIpAddress", ""),
                    "launch_time": item.get("LaunchTime").isoformat() if item.get("LaunchTime") else "",
                    "cpu_average": None,
                })
        # Query CPU for a bounded number of instances to keep page loads reasonable.
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=1)
        for item in out[:40]:
            if item["state"] != "running":
                continue
            try:
                metrics = aws_client("cloudwatch", region).get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName="CPUUtilization",
                    Dimensions=[{"Name": "InstanceId", "Value": item["id"]}],
                    StartTime=start,
                    EndTime=end,
                    Period=300,
                    Statistics=["Average"],
                ).get("Datapoints", [])
                if metrics:
                    item["cpu_average"] = round(sum(p["Average"] for p in metrics) / len(metrics), 1)
            except Exception as exc:
                log.debug("CPU metric unavailable for %s: %s", item["id"], exc)
        return out

    run("EC2 instances / CPU", instances, "ec2_instances")

    def vpcs():
        out = []
        for x in pages(ec2, "describe_vpcs", "Vpcs"):
            tags = {t["Key"]: t["Value"] for t in x.get("Tags", [])}
            out.append({"id": x.get("VpcId"), "name": tags.get("Name", ""), "cidr": x.get("CidrBlock", ""),
                        "state": x.get("State", ""), "is_default": x.get("IsDefault", False)})
        return out
    run("VPCs", vpcs, "vpcs")

    def subnets():
        out = []
        for x in pages(ec2, "describe_subnets", "Subnets"):
            tags = {t["Key"]: t["Value"] for t in x.get("Tags", [])}
            out.append({"id": x.get("SubnetId"), "name": tags.get("Name", ""), "vpc_id": x.get("VpcId", ""),
                        "cidr": x.get("CidrBlock", ""), "az": x.get("AvailabilityZone", ""),
                        "available_ips": x.get("AvailableIpAddressCount", 0),
                        "public_ip_on_launch": x.get("MapPublicIpOnLaunch", False)})
        return out
    run("Subnets", subnets, "subnets")

    def security_groups():
        out = []
        for x in pages(ec2, "describe_security_groups", "SecurityGroups"):
            out.append({"id": x.get("GroupId"), "name": x.get("GroupName", ""), "vpc_id": x.get("VpcId", ""),
                        "description": x.get("Description", ""), "ingress_rules": len(x.get("IpPermissions", [])),
                        "egress_rules": len(x.get("IpPermissionsEgress", []))})
        return out
    run("Security groups", security_groups, "security_groups")

    def route_tables():
        out = []
        for x in pages(ec2, "describe_route_tables", "RouteTables"):
            tags = {t["Key"]: t["Value"] for t in x.get("Tags", [])}
            out.append({"id": x.get("RouteTableId"), "name": tags.get("Name", ""), "vpc_id": x.get("VpcId", ""),
                        "routes": len(x.get("Routes", [])), "associations": len(x.get("Associations", []))})
        return out
    run("Route tables", route_tables, "route_tables")

    def internet_gateways():
        return [{"id": x.get("InternetGatewayId"),
                 "vpc_ids": [a.get("VpcId", "") for a in x.get("Attachments", [])],
                 "state": (x.get("Attachments") or [{}])[0].get("State", "detached")}
                for x in pages(ec2, "describe_internet_gateways", "InternetGateways")]
    run("Internet gateways", internet_gateways, "internet_gateways")

    def nat_gateways():
        return [{"id": x.get("NatGatewayId"), "vpc_id": x.get("VpcId", ""),
                 "subnet_id": x.get("SubnetId", ""), "state": x.get("State", ""),
                 "public_ips": [a.get("PublicIp", "") for a in x.get("NatGatewayAddresses", [])]}
                for x in pages(ec2, "describe_nat_gateways", "NatGateways")]
    run("NAT gateways", nat_gateways, "nat_gateways")

    def volumes():
        out = []
        for x in pages(ec2, "describe_volumes", "Volumes"):
            attachments = x.get("Attachments", [])
            out.append({"id": x.get("VolumeId"), "size_gib": x.get("Size", 0), "type": x.get("VolumeType", ""),
                        "state": x.get("State", ""), "az": x.get("AvailabilityZone", ""),
                        "encrypted": x.get("Encrypted", False),
                        "attached_instance": attachments[0].get("InstanceId", "") if attachments else "",
                        "device": attachments[0].get("Device", "") if attachments else ""})
        return out
    run("EBS volumes", volumes, "ebs_volumes")

    def asgs():
        client = aws_client("autoscaling", region)
        out = []
        for x in pages(client, "describe_auto_scaling_groups", "AutoScalingGroups"):
            out.append({"name": x.get("AutoScalingGroupName", ""), "min": x.get("MinSize", 0),
                        "desired": x.get("DesiredCapacity", 0), "max": x.get("MaxSize", 0),
                        "instances": len(x.get("Instances", [])),
                        "healthy": sum(1 for i in x.get("Instances", []) if i.get("HealthStatus") == "Healthy"),
                        "status": x.get("Status", "")})
        return out
    run("Auto Scaling groups", asgs, "auto_scaling_groups")

    def rds():
        client = aws_client("rds", region)
        return [{"id": x.get("DBInstanceIdentifier", ""), "engine": x.get("Engine", ""),
                 "status": x.get("DBInstanceStatus", ""), "class": x.get("DBInstanceClass", ""),
                 "az": x.get("AvailabilityZone", ""), "storage_gib": x.get("AllocatedStorage", 0),
                 "public": x.get("PubliclyAccessible", False)}
                for x in pages(client, "describe_db_instances", "DBInstances")]
    run("RDS", rds, "rds_instances")

    def lambdas():
        client = aws_client("lambda", region)
        return [{"name": x.get("FunctionName", ""), "runtime": x.get("Runtime", "custom"),
                 "memory_mb": x.get("MemorySize", 0), "timeout_seconds": x.get("Timeout", 0),
                 "last_modified": x.get("LastModified", ""), "state": x.get("State", "Active")}
                for x in pages(client, "list_functions", "Functions")]
    run("Lambda", lambdas, "lambda_functions")

    def lbs():
        client = aws_client("elbv2", region)
        return [{"name": x.get("LoadBalancerName", ""), "arn": x.get("LoadBalancerArn", ""),
                 "type": x.get("Type", ""), "scheme": x.get("Scheme", ""),
                 "state": x.get("State", {}).get("Code", ""), "dns": x.get("DNSName", ""),
                 "vpc_id": x.get("VpcId", "")}
                for x in pages(client, "describe_load_balancers", "LoadBalancers")]
    run("Load balancers", lbs, "load_balancers")

    def alarms():
        client = aws_client("cloudwatch", region)
        return [{"name": x.get("AlarmName", ""), "state": x.get("StateValue", ""),
                 "metric": x.get("MetricName", ""), "namespace": x.get("Namespace", ""),
                 "reason": x.get("StateReason", "")[:180]}
                for x in pages(client, "describe_alarms", "MetricAlarms")]
    run("CloudWatch alarms", alarms, "cloudwatch_alarms")

    def dynamodb():
        client = aws_client("dynamodb", region)
        names = pages(client, "list_tables", "TableNames")
        return [{"name": name} for name in names]
    run("DynamoDB", dynamodb, "dynamodb_tables")

    def ecs():
        client = aws_client("ecs", region)
        arns = pages(client, "list_clusters", "clusterArns")
        return [{"arn": arn, "name": arn.split("/")[-1]} for arn in arns]
    run("ECS clusters", ecs, "ecs_clusters")

    def eks():
        client = aws_client("eks", region)
        names = pages(client, "list_clusters", "clusters")
        return [{"name": name} for name in names]
    run("EKS clusters", eks, "eks_clusters")

    return result

def collect_global():
    result = {"s3_buckets": [], "iam_users": [], "iam_roles": [], "iam_policies": [], "global_errors": {}}

    def run(label, fn, target):
        value, error = safe_call(label, None, fn)
        result[target] = value
        if error:
            result["global_errors"][label] = error

    def s3_buckets():
        client = aws_client("s3")
        output = []
        for x in client.list_buckets().get("Buckets", []):
            name = x.get("Name", "")
            region = "unknown"
            try:
                region = client.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            except Exception:
                pass
            output.append({"name": name, "region": region,
                           "created": x.get("CreationDate").isoformat() if x.get("CreationDate") else ""})
        return output
    run("S3 buckets", s3_buckets, "s3_buckets")

    def iam_users():
        client = aws_client("iam", "us-east-1")
        out = []
        for x in pages(client, "list_users", "Users"):
            out.append({"name": x.get("UserName", ""), "id": x.get("UserId", ""),
                        "created": x.get("CreateDate").isoformat() if x.get("CreateDate") else "",
                        "password_last_used": x.get("PasswordLastUsed").isoformat() if x.get("PasswordLastUsed") else "Never/unknown"})
        return out
    run("IAM users", iam_users, "iam_users")

    def iam_roles():
        client = aws_client("iam", "us-east-1")
        return [{"name": x.get("RoleName", ""), "id": x.get("RoleId", ""),
                 "created": x.get("CreateDate").isoformat() if x.get("CreateDate") else ""}
                for x in pages(client, "list_roles", "Roles")]
    run("IAM roles", iam_roles, "iam_roles")

    def iam_policies():
        client = aws_client("iam", "us-east-1")
        return [{"name": x.get("PolicyName", ""), "arn": x.get("Arn", ""),
                 "attachment_count": x.get("AttachmentCount", 0)}
                for x in pages(client, "list_policies", "Policies", Scope="Local")]
    run("Customer IAM policies", iam_policies, "iam_policies")
    return result

def build_payload(force=False):
    global _cached_payload, _cached_at
    now = time.time()
    if not force and _cached_payload is not None and now - _cached_at < CACHE_SECONDS:
        return _cached_payload

    started = time.time()
    try:
        regions = get_regions()
    except Exception as exc:
        return {
            "ok": False,
            "error": "Could not discover AWS regions: " + short_error(exc),
            "hint": "Check the EC2 IAM role permissions for ec2:DescribeRegions and verify that this instance can reach AWS APIs.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "regions": [], "global": {}, "summary": {}
        }

    regional = []
    # Parallel regional collection helps when several regions are enabled.
    max_workers = min(8, max(1, len(regions)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        jobs = {pool.submit(collect_region, region): region for region in regions}
        for future in as_completed(jobs):
            region = jobs[future]
            try:
                regional.append(future.result())
            except Exception as exc:
                log.exception("Unexpected region collection failure: %s", region)
                regional.append({"region": region, "service_errors": {"region": short_error(exc)}})
    regional.sort(key=lambda x: x.get("region", ""))

    global_data = collect_global()
    summary = {
        "regions": len(regional),
        "ec2_instances": sum(len(x.get("ec2_instances", [])) for x in regional),
        "running_instances": sum(sum(1 for i in x.get("ec2_instances", []) if i.get("state") == "running") for x in regional),
        "vpcs": sum(len(x.get("vpcs", [])) for x in regional),
        "subnets": sum(len(x.get("subnets", [])) for x in regional),
        "ebs_volumes": sum(len(x.get("ebs_volumes", [])) for x in regional),
        "auto_scaling_groups": sum(len(x.get("auto_scaling_groups", [])) for x in regional),
        "rds_instances": sum(len(x.get("rds_instances", [])) for x in regional),
        "lambda_functions": sum(len(x.get("lambda_functions", [])) for x in regional),
        "load_balancers": sum(len(x.get("load_balancers", [])) for x in regional),
        "cloudwatch_alarms": sum(len(x.get("cloudwatch_alarms", [])) for x in regional),
        "s3_buckets": len(global_data.get("s3_buckets", [])),
        "iam_users": len(global_data.get("iam_users", [])),
        "iam_roles": len(global_data.get("iam_roles", [])),
        "dynamodb_tables": sum(len(x.get("dynamodb_tables", [])) for x in regional),
        "ecs_clusters": sum(len(x.get("ecs_clusters", [])) for x in regional),
        "eks_clusters": sum(len(x.get("eks_clusters", [])) for x in regional),
    }
    payload = {
        "ok": True, "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.time() - started, 1),
        "regions": regional, "global": global_data, "summary": summary,
    }
    _cached_payload, _cached_at = payload, time.time()
    return payload

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/dashboard")
def dashboard_api():
    return jsonify(build_payload())

@app.route("/api/refresh")
def refresh_api():
    return jsonify(build_payload(force=True))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PY

cat > templates/index.html <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudWatchX | AWS Observability</title>
<style>
:root{
 --bg:#0b1220;--panel:#111c2d;--panel2:#162338;--line:#29394e;
 --text:#e8eef7;--muted:#9aacc2;--orange:#ff9900;--orange2:#ffb84d;
 --blue:#42a5f5;--green:#43c59e;--red:#ff6b6b;--yellow:#f5c451;
}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 Arial,Helvetica,sans-serif}
a{color:var(--blue)}button,select,input{font:inherit}
.topbar{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:#080e18;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
.brand{display:flex;align-items:center;gap:12px;font-size:19px;font-weight:700;letter-spacing:.2px}
.logo{width:34px;height:34px;border-radius:9px;background:var(--orange);color:#17202e;display:grid;place-items:center;font-weight:900;font-size:20px}
.brand small{display:block;color:var(--muted);font-size:11px;font-weight:400;letter-spacing:1px;text-transform:uppercase}
.actions{display:flex;align-items:center;gap:10px}.pill{border:1px solid var(--line);border-radius:20px;padding:7px 12px;color:var(--muted);font-size:12px}
button{background:var(--orange);border:0;border-radius:5px;padding:9px 14px;color:#171d26;font-weight:700;cursor:pointer}
button:disabled{opacity:.5;cursor:wait}.layout{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:calc(100vh - 64px)}
.sidebar{padding:22px 12px;background:#0e1725;border-right:1px solid var(--line)}
.navlabel{padding:8px 12px;color:#74869d;font-size:10px;letter-spacing:1.3px;text-transform:uppercase}
.navitem{padding:11px 12px;margin:3px 0;border-radius:5px;color:#c6d2e1;cursor:pointer;display:flex;gap:10px;align-items:center}
.navitem.active,.navitem:hover{background:#263247;color:#fff;border-left:3px solid var(--orange);padding-left:9px}
.navicon{width:17px;text-align:center;color:var(--orange)}
.side-note{margin:28px 8px 0;padding:12px;border:1px solid var(--line);border-radius:7px;color:var(--muted);font-size:12px}
main{padding:24px;min-width:0}.pagehead{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:20px}
h1{font-size:25px;margin:0 0 5px;font-weight:600}.subtitle{color:var(--muted)}
.statusline{color:var(--muted);font-size:12px;margin-top:8px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:7px}
.errorbox{display:none;border:1px solid #7c3d45;background:#351f2a;color:#ffd4d4;padding:14px;border-radius:7px;margin:15px 0}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin-bottom:22px}
.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px}
.card{padding:16px;position:relative;overflow:hidden}.card:after{content:"";position:absolute;right:-18px;top:-18px;width:75px;height:75px;border-radius:50%;border:12px solid #243247;opacity:.65}
.card-label{color:var(--muted);font-size:12px}.card-value{font-size:29px;font-weight:700;margin-top:8px}.card-foot{color:var(--muted);font-size:11px;margin-top:3px}
.orange{color:var(--orange)}.green{color:var(--green)}.blue{color:var(--blue)}.yellow{color:var(--yellow)}
.panel{margin-bottom:18px;overflow:hidden}.panelhead{padding:15px 17px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}
.panelhead h2{font-size:15px;margin:0;font-weight:600}.panelbody{padding:16px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap}.toolbar input,.toolbar select{background:#0b1422;color:var(--text);border:1px solid var(--line);border-radius:5px;padding:8px 10px;min-width:150px}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;white-space:nowrap;font-size:12px}th{text-align:left;color:#aebed1;background:#172438;font-weight:600}
th,td{padding:11px 13px;border-bottom:1px solid #253349}tbody tr:hover{background:#172438}tbody tr:last-child td{border-bottom:0}
.badge{display:inline-block;border-radius:12px;padding:3px 8px;background:#25354a;color:#c8d6e6;font-size:11px}
.badge.good{background:#123d36;color:#7ce0bd}.badge.warn{background:#473a1e;color:#ffdc86}.badge.bad{background:#492831;color:#ff9ca4}
.tabs{display:flex;gap:6px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line)}
.tab{background:#172438;color:#b7c6d8;border:1px solid var(--line);padding:7px 11px;border-radius:4px;font-size:12px}
.tab.active{background:#503a1b;color:#ffd18a;border-color:#94651e}
.regionblock{margin-bottom:12px;border:1px solid var(--line);border-radius:7px;overflow:hidden}
.regiontitle{padding:13px 15px;background:#172438;display:flex;justify-content:space-between;align-items:center;cursor:pointer}
.regiontitle strong{font-size:13px}.regioncontent{display:none;padding:13px}.regioncontent.open{display:block}
.subsection{margin-bottom:16px}.subsection h3{font-size:13px;color:var(--orange2);margin:0 0 8px}
.mini{display:inline-block;margin:3px 7px 3px 0;color:var(--muted);font-size:11px}
.empty{padding:25px;text-align:center;color:var(--muted)}
footer{color:#6f829a;font-size:11px;padding:8px 0 24px}
@media(max-width:1050px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:180px minmax(0,1fr)}main{padding:16px}}
@media(max-width:720px){.layout{display:block}.sidebar{display:none}.topbar{padding:0 12px}.brand{font-size:16px}main{padding:13px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.pagehead{display:block}.actions{gap:5px}.pill{display:none}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand"><div class="logo">☁</div><div>CloudWatchX<small>AWS observability console</small></div></div>
  <div class="actions"><span class="pill" id="regionPill">Discovering regions…</span><span class="pill">Inventory + Metrics</span><button id="refreshBtn" onclick="loadDashboard(true)">↻ Refresh</button></div>
</header>
<div class="layout">
<aside class="sidebar">
  <div class="navlabel">Monitor</div>
  <div class="navitem active" data-view="overview"><span class="navicon">◈</span> Overview</div>
  <div class="navitem" data-view="compute"><span class="navicon">▣</span> Compute</div>
  <div class="navitem" data-view="network"><span class="navicon">⌘</span> Networking</div>
  <div class="navitem" data-view="storage"><span class="navicon">▤</span> Storage</div>
  <div class="navitem" data-view="database"><span class="navicon">▥</span> Databases</div>
  <div class="navitem" data-view="security"><span class="navicon">♙</span> Identity & Security</div>
  <div class="navitem" data-view="alarms"><span class="navicon">♧</span> CloudWatch & Alarms</div>
  <div class="navlabel">Scope</div>
  <div class="side-note">The dashboard discovers all AWS regions enabled for your account. IAM and S3 bucket inventory are account-wide.</div>
</aside>
<main>
  <div class="pagehead">
    <div><h1 id="pageTitle">AWS Account Overview</h1><div class="subtitle">Multi-region resource inventory with CloudWatch CPU and alarm status.</div><div class="statusline" id="lastUpdated"><span class="dot"></span>Connecting to AWS…</div></div>
  </div>
  <div id="errorBox" class="errorbox"></div>
  <section id="overviewView">
    <div class="cards" id="summaryCards"></div>
    <div class="panel">
      <div class="panelhead"><h2>Resource inventory by service</h2><span class="badge" id="scopeBadge">All enabled regions</span></div>
      <div class="panelbody" id="serviceGrid" class="servicegrid"></div>
    </div>
    <div class="panel">
      <div class="panelhead"><h2>EC2 instance CPU overview</h2><span class="badge">CloudWatch · last 60 minutes</span></div>
      <div class="tablewrap"><table><thead><tr><th>Region</th><th>Instance</th><th>Name</th><th>State</th><th>Type</th><th>Availability Zone</th><th>CPU Avg.</th><th>Private IP</th></tr></thead><tbody id="cpuTable"></tbody></table></div>
    </div>
    <div class="panel">
      <div class="panelhead"><h2>CloudWatch alarms</h2><span class="badge">All enabled regions</span></div>
      <div class="tablewrap"><table><thead><tr><th>Region</th><th>Alarm</th><th>Metric</th><th>Namespace</th><th>State</th></tr></thead><tbody id="alarmTable"></tbody></table></div>
    </div>
  </section>
  <section id="detailView" style="display:none">
    <div class="panel"><div class="panelhead"><h2 id="detailTitle">Resources</h2><div class="toolbar"><input id="searchInput" placeholder="Search visible resources…" oninput="renderDetails()"><select id="regionSelect" onchange="renderDetails()"><option value="all">All regions</option></select></div></div><div id="detailContent" class="panelbody"></div></div>
  </section>
  <footer>CloudWatchX is an independent monitoring dashboard, not an official AWS product. Inventory visibility depends on IAM permissions and the services enabled in your account. CPU datapoints can be empty when CloudWatch has no recent metric data.</footer>
</main>
</div>
<script>
let DATA=null, currentView='overview';
const SERVICE_CARDS=[
 ['ec2_instances','EC2 Instances','Compute'],['vpcs','VPCs','Networking'],['subnets','Subnets','Networking'],
 ['security_groups','Security Groups','Networking'],['ebs_volumes','EBS Volumes','Storage'],
 ['s3_buckets','S3 Buckets','Storage'],['auto_scaling_groups','Auto Scaling Groups','Compute'],
 ['rds_instances','RDS Databases','Databases'],['lambda_functions','Lambda Functions','Compute'],
 ['load_balancers','Load Balancers','Networking'],['cloudwatch_alarms','CloudWatch Alarms','Monitoring'],
 ['iam_users','IAM Users','Identity'],['iam_roles','IAM Roles','Identity'],['dynamodb_tables','DynamoDB Tables','Databases'],
 ['ecs_clusters','ECS Clusters','Containers'],['eks_clusters','EKS Clusters','Containers']
];
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function allRegional(key){return (DATA?.regions||[]).flatMap(r=>(r[key]||[]).map(x=>({...x,_region:r.region})));}
function total(key){if(key==='s3_buckets'||key==='iam_users'||key==='iam_roles')return (DATA?.global?.[key]||[]).length;return allRegional(key).length;}
function badgeState(state){let s=String(state||'unknown').toLowerCase();let cls=(['running','available','active','healthy','ok','in_service'].includes(s))?'good':(['pending','warning','insufficient_data','modifying','creating'].includes(s))?'warn':(['alarm','failed','stopped','terminated','unhealthy','error'].includes(s))?'bad':'';return `<span class="badge ${cls}">${esc(state||'Unknown')}</span>`;}
function renderSummary(){
 const items=[
  ['Enabled regions',DATA.summary.regions,'Account scope','orange'],
  ['Running EC2',DATA.summary.running_instances,`${DATA.summary.ec2_instances} total instances`,'green'],
  ['VPCs',DATA.summary.vpcs,'Across enabled regions','blue'],
  ['EBS volumes',DATA.summary.ebs_volumes,'Block storage','yellow'],
  ['CloudWatch alarms',DATA.summary.cloudwatch_alarms,'Metric alarms','orange'],
  ['Auto Scaling groups',DATA.summary.auto_scaling_groups,'Capacity management','green'],
  ['S3 buckets',DATA.summary.s3_buckets,'Account-wide','blue'],
  ['IAM users / roles',`${DATA.summary.iam_users} / ${DATA.summary.iam_roles}`,'Account-wide identity','yellow']
 ];
 document.getElementById('summaryCards').innerHTML=items.map(x=>`<div class="card"><div class="card-label">${esc(x[0])}</div><div class="card-value ${x[3]}">${esc(x[1])}</div><div class="card-foot">${esc(x[2])}</div></div>`).join('');
 document.getElementById('regionPill').textContent=`${DATA.summary.regions} enabled regions`;
 document.getElementById('lastUpdated').innerHTML=`<span class="dot"></span>Last refreshed ${new Date(DATA.generated_at).toLocaleString()} · ${DATA.duration_seconds}s collection`;
 document.getElementById('scopeBadge').textContent=`${DATA.summary.regions} regions`;
}
function renderServiceGrid(){
 document.getElementById('serviceGrid').innerHTML=`<div class="cards">${SERVICE_CARDS.map(([key,label,group])=>`<div class="card"><div class="card-label">${esc(group)}</div><div class="card-value">${total(key)}</div><div class="card-foot">${esc(label)}</div></div>`).join('')}</div>`;
}
function renderCPU(){
 let rows=allRegional('ec2_instances');
 document.getElementById('cpuTable').innerHTML=rows.length?rows.map(x=>`<tr><td>${esc(x._region)}</td><td>${esc(x.id)}</td><td>${esc(x.name)}</td><td>${badgeState(x.state)}</td><td>${esc(x.type)}</td><td>${esc(x.az)}</td><td>${x.cpu_average===null||x.cpu_average===undefined?'—':esc(x.cpu_average)+'%'}</td><td>${esc(x.private_ip||'—')}</td></tr>`).join(''):'<tr><td colspan="8" class="empty">No EC2 instances found, or access is denied.</td></tr>';
}
function renderAlarms(){
 let rows=allRegional('cloudwatch_alarms');
 document.getElementById('alarmTable').innerHTML=rows.length?rows.map(x=>`<tr><td>${esc(x._region)}</td><td>${esc(x.name)}</td><td>${esc(x.metric||'—')}</td><td>${esc(x.namespace||'—')}</td><td>${badgeState(x.state)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No metric alarms found in enabled regions.</td></tr>';
}
const VIEWS={
 compute:{title:'Compute resources',sections:[['ec2_instances','EC2 instances'],['auto_scaling_groups','Auto Scaling groups'],['lambda_functions','Lambda functions'],['ecs_clusters','ECS clusters'],['eks_clusters','EKS clusters']]},
 network:{title:'Networking resources',sections:[['vpcs','VPCs'],['subnets','Subnets'],['security_groups','Security groups'],['route_tables','Route tables'],['internet_gateways','Internet gateways'],['nat_gateways','NAT gateways'],['load_balancers','Load balancers']]},
 storage:{title:'Storage resources',sections:[['ebs_volumes','EBS volumes'],['s3_buckets','S3 buckets']]},
 database:{title:'Database resources',sections:[['rds_instances','RDS instances'],['dynamodb_tables','DynamoDB tables']]},
 security:{title:'Identity & security',sections:[['iam_users','IAM users'],['iam_roles','IAM roles'],['iam_policies','Customer-managed IAM policies'],['security_groups','Security groups']]},
 alarms:{title:'CloudWatch & alarms',sections:[['cloudwatch_alarms','CloudWatch metric alarms']]}
};
function tableFor(key,rows){
 if(!rows.length)return '<div class="empty">No resources returned for this service. Check permissions or whether the service is used.</div>';
 const preferred={
 ec2_instances:['id','name','state','type','az','cpu_average','private_ip','public_ip'],
 vpcs:['id','name','cidr','state','is_default'],subnets:['id','name','vpc_id','cidr','az','available_ips','public_ip_on_launch'],
 security_groups:['id','name','vpc_id','description','ingress_rules','egress_rules'],
 route_tables:['id','name','vpc_id','routes','associations'],internet_gateways:['id','vpc_ids','state'],
 nat_gateways:['id','vpc_id','subnet_id','state','public_ips'],
 ebs_volumes:['id','size_gib','type','state','az','encrypted','attached_instance','device'],
 auto_scaling_groups:['name','min','desired','max','instances','healthy','status'],
 rds_instances:['id','engine','status','class','az','storage_gib','public'],
 lambda_functions:['name','runtime','memory_mb','timeout_seconds','state','last_modified'],
 load_balancers:['name','type','scheme','state','dns','vpc_id'],
 cloudwatch_alarms:['name','metric','namespace','state','reason'],
 dynamodb_tables:['name'],ecs_clusters:['name','arn'],eks_clusters:['name'],
 s3_buckets:['name','region','created'],iam_users:['name','id','created','password_last_used'],
 iam_roles:['name','id','created'],iam_policies:['name','arn','attachment_count']
 };
 let keys=preferred[key]||Object.keys(rows[0]).filter(k=>k!=='_region');
 if(rows[0]._region)keys=['_region',...keys];
 const label=k=>({'_region':'Region','id':'ID','name':'Name','state':'State','type':'Type','az':'Availability Zone','cpu_average':'CPU Avg %','private_ip':'Private IP','public_ip':'Public IP','vpc_id':'VPC ID','cidr':'CIDR','is_default':'Default','available_ips':'Available IPs','public_ip_on_launch':'Public IP on launch','ingress_rules':'Ingress rule groups','egress_rules':'Egress rule groups','routes':'Routes','associations':'Associations','vpc_ids':'Attached VPCs','subnet_id':'Subnet ID','public_ips':'Public IPs','size_gib':'Size GiB','encrypted':'Encrypted','attached_instance':'Attached instance','device':'Device','min':'Min','desired':'Desired','max':'Max','instances':'Instances','healthy':'Healthy','engine':'Engine','class':'DB class','storage_gib':'Storage GiB','public':'Publicly accessible','runtime':'Runtime','memory_mb':'Memory MB','timeout_seconds':'Timeout (s)','last_modified':'Last modified','scheme':'Scheme','dns':'DNS name','metric':'Metric','namespace':'Namespace','reason':'State reason','region':'Region','created':'Created','password_last_used':'Password last used','arn':'ARN','attachment_count':'Attachments','description':'Description'}[k]||k.replaceAll('_',' '));
 const cell=(k,v)=>k==='state'||k==='status'?badgeState(v):k==='encrypted'||k==='public'||k==='is_default'||k==='public_ip_on_launch'?badgeState(v?'Yes':'No'):esc(Array.isArray(v)?v.join(', '):((v===null||v===undefined||v==='')?'—':v));
 return `<div class="tablewrap"><table><thead><tr>${keys.map(k=>`<th>${esc(label(k))}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${keys.map(k=>`<td>${cell(k,row[k])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function renderDetails(){
 if(!DATA)return;
 const view=VIEWS[currentView];if(!view)return;
 document.getElementById('detailTitle').textContent=view.title;
 const selected=document.getElementById('regionSelect').value;
 const q=document.getElementById('searchInput').value.trim().toLowerCase();
 let html='';
 for(const [key,label] of view.sections){
  let rows;
  if(['s3_buckets','iam_users','iam_roles','iam_policies'].includes(key))rows=(DATA.global?.[key]||[]).map(x=>({...x}));
  else rows=allRegional(key);
  if(selected!=='all'&&!['s3_buckets','iam_users','iam_roles','iam_policies'].includes(key))rows=rows.filter(x=>x._region===selected);
  if(q)rows=rows.filter(row=>Object.values(row).some(v=>String(v??'').toLowerCase().includes(q)));
  html+=`<div class="subsection"><h3>${esc(label)} <span class="badge">${rows.length}</span></h3>${tableFor(key,rows)}</div>`;
 }
 const errors=[];
 (DATA.regions||[]).forEach(r=>Object.entries(r.service_errors||{}).forEach(([service,error])=>errors.push(`${r.region} — ${service}: ${error}`)));
 Object.entries(DATA.global?.global_errors||{}).forEach(([service,error])=>errors.push(`Account-wide — ${service}: ${error}`));
 if(errors.length)html+=`<div class="subsection"><h3>Permission / service warnings (${errors.length})</h3><div class="empty" style="text-align:left">${errors.slice(0,25).map(esc).join('<br>')}${errors.length>25?'<br>More warnings omitted.':''}</div></div>`;
 document.getElementById('detailContent').innerHTML=html||'<div class="empty">No matching resources.</div>';
}
function setView(view){
 currentView=view;
 document.querySelectorAll('.navitem').forEach(el=>el.classList.toggle('active',el.dataset.view===view));
 document.getElementById('overviewView').style.display=view==='overview'?'block':'none';
 document.getElementById('detailView').style.display=view==='overview'?'none':'block';
 document.getElementById('pageTitle').textContent=view==='overview'?'AWS Account Overview':(VIEWS[view]?.title||'AWS Resources');
 if(view!=='overview')renderDetails();
}
document.querySelectorAll('.navitem').forEach(el=>el.addEventListener('click',()=>setView(el.dataset.view)));
async function loadDashboard(force=false){
 const btn=document.getElementById('refreshBtn');btn.disabled=true;btn.textContent='Loading…';
 const box=document.getElementById('errorBox');box.style.display='none';
 try{
  const response=await fetch(force?'/api/refresh':'/api/dashboard',{cache:'no-store'});
  const payload=await response.json();DATA=payload;
  if(!response.ok||!payload.ok){throw new Error(payload.error||'Dashboard could not load AWS inventory.');}
  renderSummary();renderServiceGrid();renderCPU();renderAlarms();
  document.getElementById('regionSelect').innerHTML='<option value="all">All regions</option>'+(DATA.regions||[]).map(r=>`<option value="${esc(r.region)}">${esc(r.region)}</option>`).join('');
  if(currentView!=='overview')renderDetails();
 }catch(err){box.style.display='block';box.textContent='Unable to load AWS data: '+err.message;}
 finally{btn.disabled=false;btn.textContent='↻ Refresh';}
}
loadDashboard();
</script>
</body>
</html>
HTML

cat > Dockerfile <<'DOCKER'
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY templates ./templates
EXPOSE 5000
CMD ["gunicorn", "--workers", "2", "--threads", "8", "--timeout", "180", "--bind", "0.0.0.0:5000", "app:app"]
DOCKER

cat > .dockerignore <<'IGNORE'
.git
__pycache__
*.pyc
*.pem
.env
venv
IGNORE

echo "[3/7] Checking Python syntax..."
python3 -m py_compile app.py

echo "[4/7] Building Docker image..."
$DOCKER build -t "$IMAGE_NAME" .

echo "[5/7] Replacing the old container if present..."
$DOCKER rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "[6/7] Starting CloudWatchX on localhost:$HOST_PORT..."
$DOCKER run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "127.0.0.1:${HOST_PORT}:${CONTAINER_PORT}" \
  -e AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-south-1}" \
  -e CACHE_SECONDS=60 \
  "$IMAGE_NAME"

echo "[7/7] Waiting for health endpoint..."
for attempt in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${HOST_PORT}/api/health" >/dev/null; then
    break
  fi
  sleep 2
done

echo
echo "=========================================================="
echo " CloudWatchX container status"
$DOCKER ps --filter "name=$CONTAINER_NAME"
echo
echo " Health endpoint:"
curl -fsS "http://127.0.0.1:${HOST_PORT}/api/health" || true
echo
echo " Logs: $DOCKER logs -f $CONTAINER_NAME"
echo " Stop: $DOCKER stop $CONTAINER_NAME"
echo "=========================================================="
echo
echo "SECURITY: the app is bound to 127.0.0.1 on the EC2 host."
echo "From your Windows PC, open PowerShell and run:"
echo 'ssh -i "C:\path\to\your-key.pem" -L 5000:127.0.0.1:5000 ec2-user@YOUR_EC2_PUBLIC_IP'
echo "Then open http://127.0.0.1:5000 in your browser."
echo
echo "If AWS inventory shows access denied, attach an EC2 IAM role with read-only permissions."
echo "Never place access keys in this script, Docker image, or source code."
