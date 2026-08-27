# Public Terraform administration ingress

This fixture declares an AWS security group whose literal ingress rule admits
the complete IPv4 internet to TCP port 22. The benchmark requires the scanner
to preserve the exact Terraform resource, ingress direction, public CIDR,
protocol, and administrative port before evaluating deployment, attachment,
routing, host exposure, authentication, and concrete compromise impact.
