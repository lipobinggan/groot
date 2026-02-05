
class Record:
    def __init__(self, name, rtype, rclass, ttl, rdata):
        self.name = name.lower()
        self.rtype = rtype.upper()
        self.rclass = rclass.upper()
        self.ttl = int(ttl) if ttl else 0
        self.rdata = rdata

    def __repr__(self):
        return f"{self.name} {self.ttl} {self.rclass} {self.rtype} {self.rdata}"

class Zone:
    def __init__(self, name, server_name):
        self.name = name.lower()
        self.server_name = server_name.lower()
        self.records = []

    def add_record(self, record):
        self.records.append(record)

    def get_records(self, name, rtype=None):
        res = []
        for r in self.records:
            if r.name == name:
                if rtype is None or r.rtype == rtype:
                    res.append(r)
        return res

class Query:
    def __init__(self, name, qtype="A"):
        self.name = name.lower()
        self.qtype = qtype
    
    def __repr__(self):
        return f"<{self.name} {self.qtype}>"
    
    def __eq__(self, other):
        return self.name == other.name and self.qtype == other.qtype
    
    def __hash__(self):
        return hash((self.name, self.qtype))
