with open("seeds/syntax.txt", "r") as seeds:
    counter = 0
    for line in seeds.readlines():
        print(line[:-1]) # remove line break at end
        with open(f"seeds/{counter}.re", "w") as new_file:
            new_file.write(line[:-1])
        counter += 1