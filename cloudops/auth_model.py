from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, ListAttribute, BooleanAttribute, MapAttribute

class Whitelist(Model):
    """
    Map DynamoDB schema 
    """
    class Meta:
        table_name = "tlsint_whitelist"
    L1_method = ListAttribute(null=True)
    level = UnicodeAttribute(range_key=True)
    role = UnicodeAttribute(hash_key=True)
    L2_rules = ListAttribute(null=True)