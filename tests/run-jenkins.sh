export PYTHONIOENCODING=UTF-8
echo "RUNNING TEST test_basic.py"
python test_basic.py
echo "RUNNING TEST test_bip32_speed.py"
python test_bip32_speed.py
echo "RUNNING TEST test_debuglink.py"
python test_debuglink.py
echo "RUNNING TEST test_ecies.py"
python test_ecies.py
echo "RUNNING TEST test_msg_applysettings.py"
python test_msg_applysettings.py
echo "RUNNING TEST test_msg_changepin.py"
python test_msg_changepin.py
echo "RUNNING TEST test_msg_cipherkeyvalue.py"
python test_msg_cipherkeyvalue.py
echo "RUNNING TEST test_msg_clearsession.py"
python test_msg_clearsession.py
echo "RUNNING TEST test_msg_estimatetxsize.py"
python test_msg_estimatetxsize.py
echo "RUNNING TEST test_msg_getaddress.py"
python test_msg_getaddress.py
echo "RUNNING TEST test_msg_getaddress_show.py"
python test_msg_getaddress_show.py
echo "RUNNING TEST test_msg_getentropy.py"
python test_msg_getentropy.py
echo "RUNNING TEST test_msg_getpublickey.py"
python test_msg_getpublickey.py
echo "RUNNING TEST test_msg_loaddevice.py"
python test_msg_loaddevice.py
echo "RUNNING TEST test_msg_ping.py"
python test_msg_ping.py
echo "RUNNING TEST test_msg_recoverydevice.py"
python test_msg_recoverydevice.py
echo "RUNNING TEST test_msg_recoverydevice_cipher.py"
python test_msg_recoverydevice_cipher.py
echo "RUNNING TEST test_msg_resetdevice.py"
python test_msg_resetdevice.py
echo "RUNNING TEST test_msg_signmessage.py"
python test_msg_signmessage.py
echo "RUNNING TEST test_msg_signtx.py"
python test_msg_signtx.py
echo "RUNNING TEST test_msg_verifymessage.py"
python test_msg_verifymessage.py
echo "RUNNING TEST test_msg_wipedevice.py"
python test_msg_wipedevice.py
echo "RUNNING TEST test_multisig_change.py"
python test_multisig_change.py
echo "RUNNING TEST test_multisig.py"
python test_multisig.py
echo "RUNNING TEST test_protect_call.py"
python test_protect_call.py
#echo "RUNNING TEST test_protection_levels.py"
#python test_protection_levels.py
echo "RUNNING TEST test_zerosig.py"
python test_zerosig.py
