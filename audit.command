#!/bin/zsh
umask 077
printf "%s\n" 'audit VPN 연결: 요청 시 Mac 로그인 암호와 OTP를 입력하세요. CONNECTED 후에는 터미널을 닫아도 연결이 유지됩니다.'
"${0:A:h}/vpn" audit
vpn_result=$?
printf "VPN command exit: %s\n" "$vpn_result"
read "vpn_done?Enter를 누르면 창을 닫을 수 있습니다: "
