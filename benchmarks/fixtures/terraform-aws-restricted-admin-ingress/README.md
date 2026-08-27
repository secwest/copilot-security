# Restricted Terraform administration ingress

This topology-matched control retains the same AWS security group and TCP port
22 but restricts the literal ingress source to the private `10.0.0.0/8`
network. It must not produce the public-administration-ingress model.
