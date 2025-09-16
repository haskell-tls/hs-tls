doms=$(cat dom-list.txt)
for dom in $doms; do
  printf '%s' $dom
  n=$(dug -f short $dom a | wc -l | awk '{print $1}')
  if [ $n -ne 0 ]; then
      printf ' a'
      if dug -f short $dom https | grep 'ech=' 1> /dev/null 2>&1; then
        printf ' ech'
      fi
  fi
  printf '\n'
done
