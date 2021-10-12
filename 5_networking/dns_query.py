import json
import dns.resolver

domain = "example.com"

TIME_DURATION_UNITS = (
    ('week', 60*60*24*7),
    ('day', 60*60*24),
    ('hour', 60*60),
    ('min', 60),
    ('sec', 1)
)

def human_time(seconds):
    if seconds == 0:
        return 'inf'
    parts = []
    for unit, div in TIME_DURATION_UNITS:
        amount, seconds = divmod(int(seconds), div)
        if amount > 0:
            parts.append('{} {}{}'.format(amount, unit, "" if amount == 1 else "s"))
    return ', '.join(parts)

answers = dns.resolver.resolve(domain, "SOA")
print(f'query qname: {answers.qname}, num ans. {len(answers)}')
for rdata in answers:
    print(f' serial  : {rdata.serial}')
    print(f' tech    : {rdata.rname}')
    print(f' refresh : {rdata.refresh}s / {human_time(rdata.refresh)}')
    print(f' retry   : {rdata.retry}s / {human_time(rdata.retry)}')
    print(f' expire  : {rdata.expire}s / {human_time(rdata.expire)}')
    print(f' minimum : {rdata.minimum}s / {human_time(rdata.minimum)}')
    print(f' mname   : {rdata.mname}')