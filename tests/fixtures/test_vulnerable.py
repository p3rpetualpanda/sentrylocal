def run_calculation(user_input):
    # Dangerous: executes arbitrary user input
    result = eval(user_input)
    return result


def safe_function():
    x = 5 + 5
    return x