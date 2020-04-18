This linux stateful firewall was built in "Workshop in Information Security" at TAU.
It includes:
- Communication with the [firewall kernel module](module/) from userspace by sysfs
- Stateless & Stateful packet inspection. Packets are handled using Netfilter api
- [Userspace interface](user/) to load and show rule table and logs
- Deep inspection in common complex protocols such as HTTP, SMTP, FTP by using [man in the middle](mitm/)
- Protection against a specific vulnerability numbered CVE-2019-17662 ([see proj.pptx for more info](proj.pptx))
