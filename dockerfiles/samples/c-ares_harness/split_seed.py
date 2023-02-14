with open("seeds/additional.txt", "r") as seeds:
    counter = 0
    for line in seeds.readlines():
        if not line.startswith("#"):
            print(line[:-1])  # remove line break at end

            with open(f"seeds/additional/{counter}.url", "w") as new_file:
                new_file.write(line[:-1])
            counter += 1