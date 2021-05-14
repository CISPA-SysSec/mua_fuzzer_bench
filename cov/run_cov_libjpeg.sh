
rm -rf libjpeg*

COUNTER=0
for file in /home/mutator/samples/libjpeg-turbo_harness/seeds/* /home/mutator/samples/libjpeg-turbo_harness/seeds/**/* ; do
    if [ -f "$file" ]
    then
          echo $file;
          kcov "libjpeg_tmp_${COUNTER}" /home/mutator/samples/libjpeg-turbo/libjpeg_turbo_fuzzer $file;
          COUNTER=$((COUNTER+1))
    fi
done

kcov --merge libjpeg libjpeg_tmp_*

rm -rf libjpeg_tmp_*
