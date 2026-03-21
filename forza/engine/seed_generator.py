from hypothesis import strategies as st
import random

# JSON Generator
def generate_json():
    strategy = st.recursive(
        st.dictionaries(st.text(min_size=1, max_size=5), st.integers()),
        lambda children: st.dictionaries(st.text(min_size=1, max_size=5), children),
        max_leaves=5
    )
    data = strategy.example()
    return str(data).replace("'", '"') # convert Python dict to JSON string

# IPv4 Generator
def generate_ipv4():
    if random.random() < 0.7: # 70% valid
        return ".".join(str(random.randint(0, 255)) for _ in range(4))
    else:
        return ".".join(str(random.randint(256, 999)) for _ in range(4)) # invalid

# IPv6 Generator
def generate_ipv6():
    def rand_hex():
        return format(random.randint(0, 65535), 'x')

    if random.random() < 0.7: # 70% valid
        return ":".join(rand_hex() for _ in range(8))
    else:
        invalids = ["::::::", "12345::abcd", "gggg::1", "1::1::1"]
        return random.choice(invalids) # invalid

# Cidrize Generator
def generate_cidr():
    ip = generate_ipv4()
    if random.random() < 0.7: # 70% valid
        return f"{ip}/{random.randint(0, 32)}"
    else:
        return f"{ip}/999" # invalid

# MAIN 
def generate_seed(input_format):
    if input_format == "json":
        return generate_json()

    elif input_format == "ipv4":
        return generate_ipv4()

    elif input_format == "ipv6":
        return generate_ipv6()

    elif input_format == "cidr":
        return generate_cidr()

    return "test"
