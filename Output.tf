output "public_ip" {
  value = aws_instance.ElizabethFolzGroup_WebApp.public_ip
}

output "db_endpoint" {
  value = aws_db_instance.elizabethfolzgroupdb.endpoint
}

output "name_servers" {
  value = aws_route53_record.ElizabethFolzGroup_Website.name
}

output "ns_records" {
  value = aws_route53_zone.elizabethfolzgroup_zone.name_servers
}

output "elb_dns" {
  value = aws_lb.elizabethfolzgroup-elb.dns_name
}

output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.elizabethfolzgroup_distribution.domain_name
}
