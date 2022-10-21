# Custom VPC
resource "aws_vpc" "ElizabethFolzGroup_VPC" {
  cidr_block       = var.VPC_cidr_block
  instance_tenancy = "default"

  tags = {
    Name = "ElizabethFolzGroup_VPC"
  }
}

# Two Public & Two Private Subnets in Diff AZ
resource "aws_subnet" "ElizabethFolzGroup_Public_SN1" {
  vpc_id            = aws_vpc.ElizabethFolzGroup_VPC.id
  cidr_block        = var.public_subnet1_cidr_block
  availability_zone = var.public_subnet1_availabilityzone

  tags = {
    Name = "ElizabethFolzGroup_Public_SN1"
  }
}

resource "aws_subnet" "ElizabethFolzGroup_Private_SN1" {
  vpc_id            = aws_vpc.ElizabethFolzGroup_VPC.id
  cidr_block        = var.private_subnet1_cidr_block
  availability_zone = var.private_subnet1_availabilityzone

  tags = {
    Name = "ElizabethFolzGroup_Private_SN1"
  }
}

resource "aws_subnet" "ElizabethFolzGroup_Public_SN2" {
  vpc_id            = aws_vpc.ElizabethFolzGroup_VPC.id
  cidr_block        = var.public_subnet2_cidr_block
  availability_zone = var.public_subnet2_availabilityzone

  tags = {
    Name = "ElizabethFolzGroup_Public_SN2"
  }
}

resource "aws_subnet" "ElizabethFolzGroup_Private_SN2" {
  vpc_id            = aws_vpc.ElizabethFolzGroup_VPC.id
  cidr_block        = var.private_subnet2_cidr_block
  availability_zone = var.private_subnet2_availabilityzone

  tags = {
    Name = "ElizabethFolzGroup_Private_SN2"
  }
}

# Custom Internet Gateway
resource "aws_internet_gateway" "ElizabethFolzGroup_IGW" {
  vpc_id = aws_vpc.ElizabethFolzGroup_VPC.id

  tags = {
    Name = "ElizabethFolzGroup_IGW"
  }
}

# Create a public route table
resource "aws_route_table" "ElizabethFolzGroup_Public_RT" {
  vpc_id = aws_vpc.ElizabethFolzGroup_VPC.id

  route {
    cidr_block = var.public_routetable_cidr_block
    gateway_id = aws_internet_gateway.ElizabethFolzGroup_IGW.id
  }

  tags = {
    Name = "ElizabethFolzGroup_Public_RT"
  }
}

# Public subnet1 attached to public route table
resource "aws_route_table_association" "ElizabethFolzGroup_Public_RTA1" {
  subnet_id      = aws_subnet.ElizabethFolzGroup_Public_SN1.id
  route_table_id = aws_route_table.ElizabethFolzGroup_Public_RT.id
}

# Public subnet2 attached to public route table
resource "aws_route_table_association" "ElizabethFolzGroup_Public_RTA2" {
  subnet_id      = aws_subnet.ElizabethFolzGroup_Public_SN2.id
  route_table_id = aws_route_table.ElizabethFolzGroup_Public_RT.id
}

# EIP for NAT Gateway
resource "aws_eip" "ElizabethFolzGroup_EIP" {
  vpc = true

  tags = {
    Name = "ElizabethFolzGroup_EIP"
  }
}

#Custom NAT Gateway
resource "aws_nat_gateway" "ElizabethFolzGroup_NGW" {
  allocation_id = aws_eip.ElizabethFolzGroup_EIP.id
  subnet_id     = aws_subnet.ElizabethFolzGroup_Public_SN1.id

  tags = {
    Name = "ElizabethFolzGroup_NGW"
  }
}

# Create a private route table
resource "aws_route_table" "ElizabethFolzGroup_Private_RT" {
  vpc_id = aws_vpc.ElizabethFolzGroup_VPC.id

  route {
    cidr_block     = var.private_routetable_cidr_block
    nat_gateway_id = aws_nat_gateway.ElizabethFolzGroup_NGW.id
  }

  tags = {
    Name = "ElizabethFolzGroup_Private_RT"
  }
}

# Private subnet1 attached to private route table
resource "aws_route_table_association" "ElizabethFolzGroup_Private_RTA1" {
  subnet_id      = aws_subnet.ElizabethFolzGroup_Private_SN1.id
  route_table_id = aws_route_table.ElizabethFolzGroup_Private_RT.id
}

# Private subnet2 attached to private route table
resource "aws_route_table_association" "ElizabethFolzGroup_Private_RTA2" {
  subnet_id      = aws_subnet.ElizabethFolzGroup_Private_SN2.id
  route_table_id = aws_route_table.ElizabethFolzGroup_Private_RT.id
}

# Two security groups (Frontend & Backend)
resource "aws_security_group" "ElizabethFolzGroup_Frontend_SG" {
  name        = "Frontend_Access"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.ElizabethFolzGroup_VPC.id

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All ICMP - IPv4"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ElizabethFolzGroup_Frontend_SG"
  }
}

resource "aws_security_group" "ElizabethFolzGroup_Backend_SG" {
  name        = "SSH_MYSQL_Access"
  description = "Enables SSH & MYSQL access"
  vpc_id      = aws_vpc.ElizabethFolzGroup_VPC.id

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.3.0/24"]
  }

  ingress {
    description = "MYSQL/Aurora"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.3.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ElizabethFolzGroup_Backend_SG"
  }
}

# DB Subnet group
resource "aws_db_subnet_group" "elizabethfolzgroup_db_sbg" {
  name       = "elizabethfolzgroup_db_sbg"
  subnet_ids = [aws_subnet.ElizabethFolzGroup_Private_SN1.id, aws_subnet.ElizabethFolzGroup_Private_SN2.id]

  tags = {
    Name = "elizabethfolzgroup_db_sbg"
  }
}

# Mysql Relational Database
resource "aws_db_instance" "elizabethfolzgroupdb" {
  allocated_storage      = 10
  identifier             = var.identifier
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = var.instance_class
  multi_az               = true
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.elizabethfolzgroup_db_sbg.id
  vpc_security_group_ids = [aws_security_group.ElizabethFolzGroup_Backend_SG.id]
  publicly_accessible    = false
}

# Media S3 bucket (Media & Code)
resource "aws_s3_bucket" "elizabethfolzgroupmedia" {
  bucket        = "elizabethfolzgroupmedia"
  force_destroy = true

  tags = {
    Name = "elizabethfolzgroupmedia"
  }
}
# Media S3 bucket policy update
resource "aws_s3_bucket_policy" "elizabethfolzgroupmediabp" {
  bucket = aws_s3_bucket.elizabethfolzgroupmedia.id
  policy = jsonencode({
    Id = "mediabucketpolicy"
    Statement = [
      {
        Action = ["s3:GetObject", "s3:GetObjectVersion"]
        Effect = "Allow"
        Principal = {
          "AWS" = "*"
        }
        Resource = "arn:aws:s3:::elizabethfolzgroupmedia/*"
        Sid      = "PublicReadGetObject"
      }
    ]
    Version = "2012-10-17"
  })
}

# Log for Media Bucket
resource "aws_s3_bucket" "elizabethfolzgroup-elblogs" {
  bucket        = "elizabethfolzgroup-elblogs"
  force_destroy = true
  tags = {
    Name = "elizabethfolzgroup-elblogs"
  }
}

# Media Bucket Log Policy Update
resource "aws_s3_bucket_policy" "elizabethfolzgrouplogsbp" {
  bucket = aws_s3_bucket.elizabethfolzgroup-elblogs.id
  policy = jsonencode({
    Id = "mediabucketlogspolicy"
    Statement = [
      {
        Action = "s3:GetObject"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Resource = "arn:aws:s3:::elizabethfolzgroup-elblogs/*"
        Sid      = "PublicReadGetObject"
      }
    ]
    Version = "2012-10-17"
  })
}

# Code S3 bucket 
resource "aws_s3_bucket" "efgroupcodebucket" {
  bucket        = "efgroupcodebucket"
  force_destroy = true

  tags = {
    Name = "efgroupcodebucket"
  }
}

resource "aws_s3_bucket_acl" "elizabethfolzgroup-code-acl" {
  bucket = aws_s3_bucket.efgroupcodebucket.id
  acl    = "private"
}

# IAM profile
resource "aws_iam_instance_profile" "ElizabethFolzGroup_IAM_Profile" {
  name = "ElizabethFolzGroup_IAM_Profile"
  role = aws_iam_role.ElizabethFolzGroup_IAM_Role.name
}

# IAM Role
resource "aws_iam_role" "ElizabethFolzGroup_IAM_Role" {
  name        = "ElizabethFolzGroup_IAM_Role"
  description = "S3 Full Permission"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "ElizabethFolzGroup_IAM_Role"
  }
}

# IAM Role Policy Attachment
resource "aws_iam_role_policy_attachment" "ElizabethFolzGroup_IAM_Policy" {
  role       = aws_iam_role.ElizabethFolzGroup_IAM_Role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# Instance Keypair
resource "aws_key_pair" "efg_key" {
  key_name   = "efg_key"
  public_key = file(var.public_key)
}

# EC2 Instance
resource "aws_instance" "ElizabethFolzGroup_WebApp" {
  ami                         = var.ami
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.ElizabethFolzGroup_Frontend_SG.id]
  subnet_id                   = aws_subnet.ElizabethFolzGroup_Public_SN1.id
  key_name                    = var.key_name
  iam_instance_profile        = aws_iam_instance_profile.ElizabethFolzGroup_IAM_Profile.id
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
echo "This is a test file" > indextest.html
sudo yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.db_name}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${var.db_username}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${var.db_password}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.elizabethfolzgroupdb.endpoint), 0)}' )@g" /var/www/html/wp-config.php
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    # Allow open access:
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
        MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.elizabethfolzgroup_cloudfront.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://efgroupcodebucket
aws s3 sync /var/www/html/ s3://efgroupcodebucket
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://efgroupcodebucket /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://elizabethfolzgroupmedia" >> /etc/crontab
sudo chkconfig httpd on
sudo service httpd start
sudo setenforce 0
  EOF
  tags = {
    Name = "ElizabethFolzGroup_WebApp"
  }
}

# Cloudfront Distribution Data
data "aws_cloudfront_distribution" "elizabethfolzgroup_cloudfront" {
  id = aws_cloudfront_distribution.elizabethfolzgroup_distribution.id
}

# Cloudfront Distribution
locals {
  s3_origin_id = "aws_s3_bucket.elizabethfolzgroupmedia.id"
}
resource "aws_cloudfront_distribution" "elizabethfolzgroup_distribution" {
  origin {
    domain_name = aws_s3_bucket.elizabethfolzgroupmedia.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 600
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Route 53 Hosted Zone
resource "aws_route53_zone" "elizabethfolzgroup_zone" {
  name          = var.domain_name
  force_destroy = true
}

# Route 53 A Record
resource "aws_route53_record" "ElizabethFolzGroup_Website" {
  zone_id = aws_route53_zone.elizabethfolzgroup_zone.zone_id
  name    = var.domain_name
  type    = "A"
  # ttl = "300" - (Use when not associating route53 to a load balancer)
  # records = [aws_instance.ElizabethFolzGroup_WebApp.public_ip]
  alias {
    name                   = aws_lb.elizabethfolzgroup-elb.dns_name
    zone_id                = aws_lb.elizabethfolzgroup-elb.zone_id
    evaluate_target_health = false
  }
}

# Target Group
resource "aws_lb_target_group" "elizabethfolzgroup-tg" {
  name     = "elizabethfolzgroup-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.ElizabethFolzGroup_VPC.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 10
    interval            = 90
    timeout             = 60
    path                = "/indextest.html"
  }
}

# Target Group Attachment
resource "aws_lb_target_group_attachment" "elizabethfolzgroup-tg-att" {
  target_group_arn = aws_lb_target_group.elizabethfolzgroup-tg.arn
  target_id        = aws_instance.ElizabethFolzGroup_WebApp.id
  port             = 80
}

# Elastic Load Balancer
resource "aws_lb" "elizabethfolzgroup-elb" {
  name                       = "elizabethfolzgroup-elb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.ElizabethFolzGroup_Frontend_SG.id]
  subnets                    = [aws_subnet.ElizabethFolzGroup_Public_SN1.id, aws_subnet.ElizabethFolzGroup_Public_SN2.id]
  enable_deletion_protection = false
  access_logs {
    bucket = "aws_s3_bucket.elizabethfolzgroup-elblogs"
    prefix = "elizabethfolzgroup"
  }
}

# Load Balancer Listerner
resource "aws_lb_listener" "elizabethfolzgroup-elb-listener" {
  load_balancer_arn = aws_lb.elizabethfolzgroup-elb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.elizabethfolzgroup-tg.arn
  }
}

# Create AMI for Web Serer
resource "aws_ami_from_instance" "ElizabethFolzGroup_ami" {
  name                    = "ElizabethFolzGroup_ami"
  source_instance_id      = aws_instance.ElizabethFolzGroup_WebApp.id
  snapshot_without_reboot = true
}

# Launch Configuration
resource "aws_launch_configuration" "ElizabethFolzGrouplc" {
  name_prefix                 = "ElizabethFolzGrouplc"
  image_id                    = aws_ami_from_instance.ElizabethFolzGroup_ami.id
  instance_type               = var.instance_type
  iam_instance_profile        = aws_iam_instance_profile.ElizabethFolzGroup_IAM_Profile.id
  security_groups             = [aws_security_group.ElizabethFolzGroup_Frontend_SG.id]
  associate_public_ip_address = true
  key_name                    = var.key_name
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
touch indextest.html
echo "This is a test file" > indextest.html
sudo yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'elizabethfolzgroupdb' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'admin' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'Admin123' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.elizabethfolzgroupdb.endpoint), 0)}' )@g" /var/www/html/wp-config.php
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    # Allow open access:
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
        MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.elizabethfolzgroup_cloudfront.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://elizabethfolzgroup-code
aws s3 sync /var/www/html/ s3://elizabethfolzgroup-code
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://elizabethfolzgroup-code /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://elizabethfolzgroupmedia" >> /etc/crontab
sudo chkconfig httpd on
sudo service httpd start
sudo setenforce 0
EOF
  lifecycle {
    create_before_destroy = false
  }
}

# Autoscaling Group
resource "aws_autoscaling_group" "ElizabethFolzGroup_asg" {
  name                      = "ElizabethFolzGroup_asg"
  desired_capacity          = 3
  max_size                  = 3
  min_size                  = 2
  health_check_grace_period = 1800
  default_cooldown          = 60
  health_check_type         = "ELB"
  force_delete              = true
  launch_configuration      = aws_launch_configuration.ElizabethFolzGrouplc.name
  vpc_zone_identifier       = [aws_subnet.ElizabethFolzGroup_Public_SN1.id, aws_subnet.ElizabethFolzGroup_Public_SN2.id]
  target_group_arns         = ["${aws_lb_target_group.elizabethfolzgroup-tg.arn}"]
  tag {
    key                 = "Name"
    value               = "ElizabethFolzGroup_asg"
    propagate_at_launch = true
  }
}
# Autoscaling Group Policy
resource "aws_autoscaling_policy" "ElizabethFolzGroup_asg_pol" {
  name                   = "ElizabethFolzGroup_asg_pol"
  policy_type            = "TargetTrackingScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.ElizabethFolzGroup_asg.name
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60.0
  }
}

# Cloudwatch Dashboard
resource "aws_cloudwatch_dashboard" "ElizabethFolzGroup_webdashboard" {
  dashboard_name = "ElizabethFolzGroup_webdashboard"
  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.ElizabethFolzGroup_WebApp.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "EC2 Instance CPU"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "NetworkIn",
            "InstanceId",
            "${aws_instance.ElizabethFolzGroup_WebApp.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "EC2 Network In"
      }
    }
  ]
 }
EOF
}

#SNS Alarms Topic
resource "aws_sns_topic" "ElizabethFolzGroup_alarmstopic" {
  name            = "ElizabethFolzGroup_alarmstopic"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
  provisioner "local-exec" {
    command = "aws sns subscribe --topic-arn arn:aws:sns:us-east-1:670390228985:ElizabethFolzGroup_alarmstopic --protocol email --notification-endpoint elizabethfolzgroup@gmail.com"
  }
}

# Cloudwatch metric alarm for CPU utilisation 
resource "aws_cloudwatch_metric_alarm" "ElizabethFolzGroup_metricalarm" {
  alarm_name          = "ElizabethFolzGroup_metricalarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.ElizabethFolzGroup_asg.name}"
  }
  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_autoscaling_policy.ElizabethFolzGroup_asg_pol.arn]
}

# Cloudwatch metric alarm for health
resource "aws_cloudwatch_metric_alarm" "ElizabethFolzGroup_metrichealthalarm" {
  alarm_name          = "ElizabethFolzGroup_healthalarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "1"
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.ElizabethFolzGroup_asg.name}"
  }
  alarm_description = "This metric monitors ec2 health status"
  alarm_actions     = ["${aws_autoscaling_policy.ElizabethFolzGroup_asg_pol.arn}"]
}