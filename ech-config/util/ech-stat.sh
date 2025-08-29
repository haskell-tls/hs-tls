doms=$(cat dom-list.txt)
for dom in $doms; do
  printf '%s' $dom
  if dug $dom a 1> /dev/null 2>&1; then
      printf ' a'
      if dug $dom https | grep 'ech=' 1> /dev/null 2>&1; then
        printf ' ech'
      fi
  fi
  printf '\n'
done

