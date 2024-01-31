from flask import Flask, render_template
app = Flask(__name__)

class SecurityGroup:
    def __init__(self, group_id, group_name, description, vpc_id, ingress_rules, egress_rules):
        self.group_id = group_id
        self.group_name = group_name
        self.description = description
        self.vpc_id = vpc_id
        self.ingress_rules = ingress_rules
        self.egress_rules = egress_rules

    def print_ingress_rules(self):
        print("Ingress Rules:")
        for rule in self.ingress_rules:
            print(f"  {rule}")
        print()

    def print_egress_rules(self):
        print("Egress Rules:")
        for rule in self.egress_rules:
            print(f"  {rule}")
        print()

@app.route('/')
def index():
    # Test security group generation
    my_security_group = SecurityGroup(
        group_id='sg-12345678',
        group_name='MySecurityGroup',
        description='Example security group',
        vpc_id='vpc-87654321',
        ingress_rules=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ],
        egress_rules=[]
    )

    return render_template('index.html', security_group=my_security_group)

if __name__ == '__main__':
    app.run(debug=True)
