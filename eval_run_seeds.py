import json

found_false = set()

with open("found_mutations.csv", "r") as found:
    with open("fuzz_target.ll.mutationlocations", "r") as location_file:
        for line in found.readlines():
            if "False" in line:
                found_false.add(int(line.split(",")[0]))
        locations = json.load(location_file)
        for location in locations:
            if int(location["UID"]) in found_false:
                found_false.remove(int(location["UID"]))

print(found_false)