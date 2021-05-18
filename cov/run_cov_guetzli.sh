
rm -rf guetzli*

COUNTER=0
for file in /home/mutator/samples/libjpeg-turbo_harness/seeds/* /home/mutator/samples/libjpeg-turbo_harness/seeds/**/*; do
  if [ -f "$file" ]
  then
    echo $file;
    kcov "guetzli_tmp_${COUNTER}" /home/mutator/samples/guetzli/fuzz_target $file;
    COUNTER=$((COUNTER+1))
  fi
done

kcov --merge guetzli guetzli_tmp_*

rm -rf guetzli_tmp_*
