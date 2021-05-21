
NAME="magic_fuzzer"
rm -rf "${NAME}*"

COUNTER=0
for file in /home/mutator/samples/file_harness/seeds/* /home/mutator/samples/file_harness/seeds/**/*; do
  if [ -f "$file" ]
  then
    echo $file;
    kcov "${NAME}_tmp_${COUNTER}" /home/mutator/samples/file/magic_fuzzer /home/mutator/samples/file_harness/magic.mgc $file;
    COUNTER=$((COUNTER+1))
  fi
done

kcov --merge "${NAME}" "${NAME}_tmp_"*

rm -rf "${NAME}_tmp_"*
