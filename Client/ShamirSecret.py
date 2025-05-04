import random
PRIME_Q = 6458713 # Prime number 
min_threshold = 3

def calculate_Y(x, poly):
    y, temp = 0, 1
    for coeff in poly: 
        y = (y + (coeff * temp)) % PRIME_Q
        temp = (temp * x) % PRIME_Q
    return y

def generate_share(shamir_secret, points):
    poly = [shamir_secret]
    for _ in range(min_threshold - 1):
        poly.append(random.randint(1, PRIME_Q - 1))

    return {x: calculate_Y(x, poly) for x in points}

def reconstruct_secret(points):
    # Reconstructs the secret using Lagrange interpolation
    secret = 0

    if len(points) < min_threshold:
        print("Could not Reconstruct Share")
        return False

    selected_points = list(points.items())[:min_threshold]
    secret = 0

    for xi, yi in selected_points:
        num = 1
        den = 1
        for xj, _ in selected_points:
            if xi != xj:
                num = (num * (-xj)) % PRIME_Q
                den = (den * (xi - xj)) % PRIME_Q
        
        den_inv = pow(den, -1, PRIME_Q)     # modular inverse
        term = (yi * num * den_inv) % PRIME_Q
        secret = (secret + term) % PRIME_Q

    return secret
