import json

found_false = set()
found_crashed = set()
crashing = list()

with open("found_mutations.csv", "r") as found:
    with open("fuzz_target.ll.mutationlocations", "r") as location_file:
        for line in found.readlines():
            if "False" in line:
                found_false.add(int(line.split(",")[0]))
            elif "Crashed" in line:
                found_crashed.add(int(line.split(",")[0]))

        locations = json.load(location_file)
        for location in locations:
            if int(location["UID"]) in found_false:
                found_false.remove(int(location["UID"]))
            elif int(location["UID"]) in found_crashed:
                crashing.append(location)

print(found_false)

for crs in crashing:
    print(crs)