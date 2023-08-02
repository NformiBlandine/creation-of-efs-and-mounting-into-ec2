terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

#define the provider
provider "aws" {
 region = "ca-central-1" 
   
}

#create the vpc
resource "aws_vpc" "efs_vpc_bla"{
    cidr_block = "172.31.0.0/16"
    tags = {
        name = "efs_vpc_bla"
    }
}

#create the subnet
resource "aws_subnet" "efs_subnet_bla" {
    tags = {
        name = "efs_subnet_bla"
    }
    vpc_id = aws_vpc.efs_vpc_bla.id
    cidr_block = "172.31.250.160/29"
    map_public_ip_on_launch = true
    depend_on = [aws_vpc.efs_vpc_bla]

    }

    #define route table
    resource "aws_route_table" "efs_routetb_bla" {
tag = {
    name = "efs_routetb_bla"
}
vpc_id = aws_vpc.efs_vpc_bla.id
    }

    #associate subnet with routing table
    resource "aws_route_table_association" "efs_ass_bla"{
      subnet_id = aws_subnet.efs_subnet_bla.id
      route_table_id = aws_route_table.efs_routetb_bla.id
    }
#create internet gateway for server to be connected to the internet
resource "aws_internet_gateway" "efs_gate_bla" {
    tags = {
        name = "efs_gate_bla"
    }
    vpc_id = aws_vpc.efs_vpc_bla.id
    depends_on = [aws_vpc.efs_vpc_bla]
}

#adding a default route in the routing table to point to the internet gateway
resource "aws_route" "default_route" {
    route_table_id = aws_route_table.efs_routetb_bla.id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.efs_gate_bla.vpc_id

}

#create a security group
resource "aws_security_group" "efs_SG" {
    name = "efs_SG"
    description = "allow web inbound traffic"
    vpc_id = aws_vpc.efs_vpc_bla.id
ingress = [
        {
            from_port       = 80
            to_port         = 80
            protocol        = "tcp"
            cidr_blocks     = ["0.0.0.0/0"]
        },
        {
            from_port       = 443
            to_port         = 443
            protocol        = "tcp"
            cidr_blocks     = ["0.0.0.0/0"]
        },
        {
            from_port       = 22
            to_port         = 22
            protocol        = "tcp"
            cidr_blocks     = ["0.0.0.0/0"]
        }
    ]

    
    ingress {
        from_port       = 2049
        to_port         = 2049
        protocol        = "tcp"
        security_groups = ["${aws_security_group.ec2.id}"]
    }

    egress {
        from_port       = 0
        to_port         = 0
        protocol        = "-1"
        cidr_blocks     = ["0.0.0.0/0"]
    }
}

#create a private key which can be used to ssh into the efs_server
resource "tis_private_key" "efs_key" {
    algorithm = "RSA"

}
#save the public key attrivute from the generated key
resource "aws_key_pair" "efs_key" {
    key_name = "efs_key"
    publlic_key = tis_private_key.efs_key.public_key_openssh
} 

#create your efs_server
resource "aws_instance" "bla_server1" {
    ami = "ami-0ea18256de20ecdfc"
    instance_type = "t2.micro"
    tag = {
        name = "bla_server1"
    }
    count = 1
    subnet_id = aws_subnet.efs_subnet_bla.id
    key_name = "efs_key"
    security_groups = [aws_security_group.efs_SG.id]
}

#creating efs file system
resource "aws_efs_file_system" "myefs" {
 depends_on = [ aws_security_group.efs_SG,aws_instance.bla_server]
 creation_token = "myefs"
 tags = {
    name = "myefs"
 }   
} 
 #mounting efs to ec2
 resource "aws_efs_mount_target" "mount" {
    depends_on = [ aws_efs_file_system.myefs]
    file_system_id = aws_efs_system.myefs.id
    subnet_id = aws_subnet.efs_subnet_bla.id
    security_groups = ["{aws_security_group.efs_SG.id}"]

 }

 resource "null_resource" "ec2_mount" {
    depends_on = [ aws_efs_mount_target.mount]
    connection {
      type = "ssh"
      user = "ubuntu"
      private_key = t1s_private_key.efs_key.private_key_pem
      host = aws_instance.bla_server.public_ip

    }
provisioner "remote-exec" {
    inline = [
        "sudo mount -t nfs4 ${aws_efs_mount_target.mount.ip_address}:/ /var/www/html"
    ]
}

 }