## STS
This is the service that issues temporary credentials (`ASIA` + SessionToken). It's the engine that makes everything else on this list possible.
## Instance Profile
This is the "container" that connects an IAM role to an EC2 instance. There's a detail here that trips a lot of people up:

- An IAM role can't be attached directly to an EC2 instance. It has to be "wrapped" in an Instance Profile.
```json
Instance Profile
    └── IAM Role
            ├── Trust Policy
            └── Permission Policy (Identity Policy)
```
When you launch an EC2 instance with a role attached through the console, AWS actually creates the Instance Profile for you automatically (same name as the role, which is why almost nobody notices it exists). But if you do it through the CLI or Terraform, you have to create it explicitly:
```json
aws iam create-instance-profile --instance-profile-name MyProfile
aws iam add-role-to-instance-profile --instance-profile-name MyProfile --role-name MyRole
aws ec2 associate-iam-instance-profile --instance-id i-xxxx --iam-instance-profile Name=MyProfile
```
Why does this exist? It's what allows the metadata service (IMDS) at `169.254.169.254` to hand out credentials automatically to the instance, the Instance Profile is the bridge between "this machine" and "this role." This is exactly what we exploited in [[Burned-Notes/AWS/Labs/SSRF IMDSv1 - Steal AWS STS Credentials|SSRF IMDSv1 - Steal AWS STS Credentials]]: the attacker requests credentials from IMDS, and IMDS pulls them from the role attached via the Instance Profile.
## Identity Policy (Permission Policy)
This is the JSON document that defines what the role (or user/group) can actually do once it has already assumed the identity.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```
It answers the question "I already am this role, what actions am I allowed to take?" It's attached directly to the role (or user), either as a managed policy or an inline one.

To keep this short: `Managed Policies` are basically the `GPOs` of Active Directory, reusable permission templates that you can attach to any `Role/User/Service` in AWS.

`Inline Policies`, on the other hand, are extremely granular permissions that only live inside a single object and can't be reused elsewhere. If you want to replicate one, you have to write it from scratch again. And if you delete the parent object, the Inline Policy gets deleted along with it.
## Managed Policy
To see the Managed Policies attached to a user or role:
```json
aws iam list-attached-user-policies --user-name '<Username>'

{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}

aws iam list-attached-role-policies --role-name '<Rolename>'

{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```
If you want to see the exact permissions a Managed Policy grants, you first need to know which version that policy is on, so you'd run:
```json
aws iam get-policy --policy-arn 'arn:aws:iam::aws:policy/AdministratorAccess'
{
    "Policy": {
        "PolicyName": "AdministratorAccess",
        "PolicyId": "ANPAIWMBCKSKIEE64ZLYK",
        "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 2,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Provides full access to AWS services and resources.",
        "CreateDate": "2015-02-06T18:39:46+00:00",
        "UpdateDate": "2015-02-06T18:39:46+00:00",
        "Tags": []
    }
}
```
And with the version (`v1` in this case) we can now use `aws iam get-policy-version`:
```json
aws iam get-policy-version --policy-arn 'arn:aws:iam::aws:policy/AdministratorAccess' --version-id 'v1'

{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2015-02-06T18:39:46+00:00"
    }
}
```
In this case, this Managed Policy grants full permissions on every resource to do basically anything.
## Inline Policy
To list Inline Policies:
```json
aws iam list-role-policies --role-name 'ec2-role-s3'

{
    "PolicyNames": [
        "PoC"
    ]
}
```
That's just an entry for an Inline Policy, at this point we only see its name. To actually see what permissions that Inline Policy grants, we need:
```json
aws iam get-role-policy --role-name 'ec2-role-s3' --policy-name 'PoC'

{
    "RoleName": "ec2-role-s3",
    "PolicyName": "PoC",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": "ec2:DescribeAccountAttributes",
                "Resource": "*"
            }
        ]
    }
}
```
And here we can see exactly what this Inline Policy allows.
## Trust Policy
This is the one that gets confused with the previous one the most, but it plays a completely different role. It answers the question: WHO is allowed to assume me (become me)?
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/CompromisedRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```
It doesn't define what the role can do, it defines who can become the role. It's attached directly to the role as part of its configuration (`AssumeRolePolicyDocument`), not as a separate policy you attach on top.
- `Trust Policy`: the guest list at the club's door (who's allowed in)
- `Identity Policy`: what you can do once you're already inside (which tables, which bar, what's VIP)

The easiest way to check this is:
```json
aws iam get-role --role-name '<Rolename>'

{
    "Role": {
        "Path": "/",
        "RoleName": "ec2-role-s3",
        "RoleId": "AROAV5BWR3XE7ML6PMTV6",
        "Arn": "arn:aws:iam::405988826569:role/ec2-role-s3",
        "CreateDate": "2026-06-29T20:58:44+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Allows EC2 instances to call AWS services on your behalf.",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {
            "LastUsedDate": "2026-07-02T04:43:06+00:00",
            "Region": "us-east-1"
        }
    }
}
```
There's a lot of info here about the role, but the part that matters most to us is:
```json
{
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
```
The `Principal` key defines which objects are allowed to assume this role. In this case, EC2 instances (though this doesn't mean *every* EC2 instance can assume this role, remember there's this thing called an `Instance Profile` that's the actual link between the role and a specific instance).
## sts:AssumeRole
This is the verb/action that actually performs the identity switch, and for it to work it needs the green light from both sides:
```cpp
┌─────────────────┐         sts:AssumeRole          ┌──────────────────┐
│  Source Role     │ ───────────────────────────────>│  Target Role      │
│  (compromised)   │                                  │  (admin, e.g.)    │
│                  │                                  │                   │
│  Identity Policy │  needs permission for:           │  Trust Policy     │
│  must allow      │  "sts:AssumeRole" on the         │  must allow       │
│  the ACTION      │  target role's ARN               │  the PRINCIPAL    │
└─────────────────┘                                  └──────────────────┘
```
Double lock, two different directions:
- **Source side** (Identity Policy of the compromised role): needs explicit permission to run `sts:AssumeRole` against the target role's ARN.
- **Target side** (Trust Policy of the admin role): needs to list the source role as an allowed `Principal`.
If either one is missing, `AssumeRole` fails with `AccessDenied`.
## Something I noticed
Not sure if this is something new or if it's always been there, but here's the scenario:

We compromise the `ec2-role-s3` role and notice `admin-role`'s Trust Policy has its Principal pointing at `ec2-role-s3` (its ARN):
```json
{
    "Role": {
        "Path": "/",
        "RoleName": "role-admin",
        "RoleId": "AROAV5BWR3XE27QN3VFUU",
        "Arn": "arn:aws:iam::405988826569:role/role-admin",
        "CreateDate": "2026-07-02T01:28:45+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement1",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::405988826569:role/ec2-role-s3"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {
            "LastUsedDate": "2026-07-02T04:54:09+00:00",
            "Region": "us-east-1"
        }
    }
}
```
But if we look at `ec2-role-s3`'s Managed/Inline Policies, there's nothing related to `sts:AssumeRole` in either of them. At first glance you'd think you're stuck, but oddly enough, running `assume-role` works perfectly fine:
```json
aws sts assume-role --role-arn 'arn:aws:iam::405988826569:role/role-admin' --role-session-name 'PoC'

{
    "Credentials": {
        "AccessKeyId": "ASIAV5BWR..SNIFF..UCD6WD",
        "SecretAccessKey": "0bOD4lQ/6O1..SNIFF..v3OHmOGcFF/8TN",
        "SessionToken": "IQoJb3JpZ2luX2VjEDQaCXVzLWVhc3QtMSJHMEUCIQCXZMaDG40lmdoxGP83QQokzX17Ki+He2fT5fNxYbqWVgIgX4..SNIFF..BgwBeSyaV5rcBakc+l1+VcO1QMCB5URVaCwqmQII/f//////////ARAAGgw0MDU5ODg4MjY1NjkiDDw6ZnU+.SNIFF..+CpYQ0J84NGoGyBCjuuqiQuXmRwhT9op7GKKAQq+onkpYPZuP73KvNMSfmppJdBWV3mMAY1E/93OkmQaemGI4hjNtk51hin+lmTsdXzDM3ZzSomGCn0C+fNB10mFdzgy5K/SRzcn5im3XRARyn/4Rt6k+rLs48I=",
        "Expiration": "2026-07-02T20:40:06+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAV5BWR3XE27QN3VFUU:PoC",
        "Arn": "arn:aws:sts::405988826569:assumed-role/role-admin/PoC"
    }
}
```

`sts:AssumeRole`: Doesn't need permission in the source's Identity Policy when the Trust Policy already grants us explicit access as the Principal.
- The Trust Policy, on its own, is enough to authorize `AssumeRole` when the Principal is a specific identity rather than a service.

So when does the Identity Policy permission actually matter?

This connects back to something we touched on earlier, and it's worth correcting here. The source's Identity Policy only matters in one specific case: when the Principal in the Trust Policy is generic, like a full account number (`arn:aws:iam::123456789012:root`) instead of a specific role/user ARN.
```json
{
  "Principal": {
    "AWS": "arn:aws:iam::405988826569:root"
  }
}
```
This is the part that trips almost everyone up the first time they see it. When you see this on a Principal, it does not mean "only the root user can assume this role." It means something much broader:

- "I trust the entire account `405988826569`", meaning any IAM identity (user or role) that exists within that account, as long as that identity also has explicit `sts:AssumeRole` permission of its own.
It's an ARN at the account level, not at the specific-identity level. Compare:

| Principal | Specificity level | Who it applies to |
|---|---|---|
| `arn:aws:iam::405988826569:role/ec2-role-s3` | Specific identity | Only that exact role |
| `arn:aws:iam::405988826569:user/juan` | Specific identity | Only that exact user |
| `arn:aws:iam::405988826569:root` | Entire account | Any identity in that account |

We'll leave this for another entry, but the short version: AWS has a feature that lets you create separate accounts, each with its own AWS environment. Those accounts get organized under `Organizational Units`, pretty much the same concept as OUs in `AD`.
