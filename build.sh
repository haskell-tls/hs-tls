cab delete -r ech-config
for pkg in ech-config tls tls-session-manager
do
(cd $pkg; cab clean; cab install)
done
