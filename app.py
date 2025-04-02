def process_data(data):
    return data.upper()

def main():
    user_input = input("Enter some text: ")
    result = process_data(user_input)
    print(f"Processed: {result}")

if __name__ == "__main__":
    main()