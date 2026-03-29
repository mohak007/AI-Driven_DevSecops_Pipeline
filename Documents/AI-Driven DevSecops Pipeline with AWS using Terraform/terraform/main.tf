# =============================================================================
# AI-DevSecOps Pipeline — Terraform Infrastructure
# Region: ap-south-1 (Mumbai)
#
# KEY FIXES vs your original:
#   1. Jenkins runs ON the host (not inside Docker container)
#      → Solves the "docker: not found" error in every pipeline stage
#   2. jenkins user added to docker group BEFORE Jenkins starts
#      → No sudo needed inside pipelines
#   3. Ports 5000, 5601, 9200 added to security group
#      → Flask app, Kibana, Elasticsearch accessible
#   4. Trivy installed at boot time
#      → Security scan stage works immediately
#   5. Python3 + ML libs pre-installed
#      → Phase 3 AI engine ready
#   6. 4 GB swap added
#      → Prevents OOM when ELK starts (Phase 2)
#   7. 30 GB root volume (up from default 8 GB)
#      → Docker images + Jenkins workspace + ELK data
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------
resource "aws_vpc" "devsecops" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name    = "devsecops-vpc"
    Project = "ai-devsecops"
  }
}

# -----------------------------------------------------------------------------
# Internet Gateway
# -----------------------------------------------------------------------------
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.devsecops.id

  tags = {
    Name = "devsecops-igw"
  }
}

# -----------------------------------------------------------------------------
# Public Subnet
# -----------------------------------------------------------------------------
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.devsecops.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-south-1a"

  tags = {
    Name = "devsecops-public-subnet"
  }
}

# -----------------------------------------------------------------------------
# Route Table
# -----------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.devsecops.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "devsecops-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# -----------------------------------------------------------------------------
# Security Group
# -----------------------------------------------------------------------------
resource "aws_security_group" "jenkins" {
  name        = "devsecops-sg"
  description = "Jenkins + DevSecOps pipeline security group"
  vpc_id      = aws_vpc.devsecops.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Jenkins UI"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Flask app (Phase 1)"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Kibana (Phase 2)"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Elasticsearch VPC only not public"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "devsecops-sg"
    Project = "ai-devsecops"
  }
}

# -----------------------------------------------------------------------------
# SSH Key Pair
# -----------------------------------------------------------------------------
resource "tls_private_key" "jenkins_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "jenkins" {
  key_name   = "devsecops-key"
  public_key = tls_private_key.jenkins_key.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.jenkins_key.private_key_pem
  filename        = "${path.module}/devsecops-key.pem"
  file_permission = "0400"
}

# -----------------------------------------------------------------------------
# EC2 Instance
# -----------------------------------------------------------------------------
resource "aws_instance" "jenkins" {
  ami                    = "ami-0f5ee92e2d63afc18"  # Ubuntu 22.04 LTS, ap-south-1
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.jenkins.id]
  key_name               = aws_key_pair.jenkins.key_name

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }

  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail
    exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1
    echo "=== Bootstrap started: $(date) ==="

    # -------------------------------------------------------------------
    # STEP 1: System packages
    # -------------------------------------------------------------------
    apt-get update -y
    apt-get install -y \
      curl wget gnupg lsb-release ca-certificates \
      git python3 python3-pip unzip jq

    # -------------------------------------------------------------------
    # STEP 2: Docker (official repo — Ubuntu's docker.io is outdated)
    # Installing from Docker's own apt repo gives us the latest stable
    # version and the compose plugin.
    # -------------------------------------------------------------------
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
      https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    systemctl start docker
    systemctl enable docker

    # -------------------------------------------------------------------
    # STEP 3: Java 17 (Jenkins requires Java 11+)
    # -------------------------------------------------------------------
    apt-get install -y openjdk-17-jdk
    java -version

    # -------------------------------------------------------------------
    # STEP 4: Jenkins — installed DIRECTLY on the host, NOT in Docker.
    #
    # WHY: If Jenkins runs inside a Docker container, pipeline stages that
    # call "docker build" cannot reach the host Docker daemon. The result
    # is exactly the error you saw: "docker: not found".
    #
    # Running Jenkins on the host means it shares the host's PATH and
    # can call /usr/bin/docker directly.
    # -------------------------------------------------------------------
    mkdir -p /usr/share/keyrings

    curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io.key \
      | gpg --dearmor -o /usr/share/keyrings/jenkins-keyring.asc

    echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
      https://pkg.jenkins.io/debian-stable binary/" \
      > /etc/apt/sources.list.d/jenkins.list

    apt-get update -y
    apt-get install -y jenkins

    # -------------------------------------------------------------------
    # CRITICAL: Add jenkins to docker group BEFORE starting Jenkins.
    #
    # If Jenkins starts first, then you add the group, the running
    # Jenkins process still has the old group list — it won't have docker
    # access until it restarts. Do it in this order: add group → start.
    # -------------------------------------------------------------------
    usermod -aG docker jenkins
    usermod -aG docker ubuntu

    systemctl start jenkins
    systemctl enable jenkins

    # -------------------------------------------------------------------
    # STEP 5: Trivy — vulnerability scanner used in Phase 5 pipeline
    # Pre-installing means the Trivy scan stage works on first run.
    # -------------------------------------------------------------------
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin
    trivy --version

    # -------------------------------------------------------------------
    # STEP 6: Python3 ML libraries (Phase 3 AI engine)
    # -------------------------------------------------------------------
    pip3 install --break-system-packages \
      pandas scikit-learn requests elasticsearch flask

    # -------------------------------------------------------------------
    # STEP 7: Swap space
    #
    # t3.medium = 4 GB RAM. ELK stack alone needs ~2.5 GB at startup.
    # Without swap, the OS kills processes (OOM) when all 3 services
    # (Jenkins + Elasticsearch + Kibana) are running together.
    # 4 GB swap gives you a safety buffer.
    # -------------------------------------------------------------------
    fallocate -l 4G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab

    # -------------------------------------------------------------------
    # Done
    # -------------------------------------------------------------------
    echo "=== Bootstrap completed: $(date) ==="
    echo "Jenkins UI:      http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080"
    echo "Initial password: $(cat /var/lib/jenkins/secrets/initialAdminPassword 2>/dev/null || echo 'not ready yet — wait 2 min')"
  USERDATA

  tags = {
    Name    = "jenkins-devsecops"
    Project = "ai-devsecops"
    Phase   = "1-6"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "public_ip" {
  description = "EC2 public IP — paste into Jenkinsfile as EC2_HOST"
  value       = aws_instance.jenkins.public_ip
}

output "jenkins_url" {
  description = "Jenkins web UI — wait ~3 minutes after terraform apply"
  value       = "http://${aws_instance.jenkins.public_ip}:8080"
}

output "ssh_command" {
  description = "SSH into instance"
  value       = "ssh -i devsecops-key.pem ubuntu@${aws_instance.jenkins.public_ip}"
}

output "get_initial_password" {
  description = "Run after SSH to get Jenkins admin password"
  value       = "sudo cat /var/lib/jenkins/secrets/initialAdminPassword"
}

output "check_bootstrap_log" {
  description = "Run after SSH to verify bootstrap ran correctly"
  value       = "sudo tail -50 /var/log/user-data.log"
}
