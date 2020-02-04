python -u sniff_ap.py mon0 >> accesspoints_`date +%Y%m%d.%H%M`.log &
python -u sniff_mac.py mon0 >> macassoc_`date +%Y%m%d.%H%M`.log &
read -p "Press any key to stop collection... " -n1 -s
killall python
zip collect_`date +%Y%m%d.%H%M`.zip *.log -9 -T
rm *.log
