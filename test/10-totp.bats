#!/usr/bin/env bats

KEY='YW2N4W7UBAIAEVCT'

KEYFILE='YW2N4W7UBAIAEVCT
" WINDOW_SIZE 3
" TOTP_AUTH
48620924
62845873
18191372
38435027
50135452
'

@test "totp: generate token" {
    run faketime '2019-05-19 07:36:43' totp "$KEY"
    cat << EOF
--- output
$output
--- output
EOF

    [ "$output" = "734544" ]
}

@test "totp: token from previous offset" {
    run faketime '2019-05-19 07:36:43' totp "$KEY" 30 -30
    cat << EOF
--- output
$output
--- output
EOF

    [ "$output" = "648256" ]
}

@test "totp: token from next offset" {
    run faketime '2019-05-19 07:36:43' totp "$KEY" 30 30
    cat << EOF
--- output
$output
--- output
EOF

    [ "$output" = "335736" ]
}

@test "totp: read key from stdin" {
    run sh -c "echo $KEY | faketime '2019-05-19 07:36:43' totp - 30 -90"
    cat << EOF
--- output
$output
--- output
EOF

    [ "$output" = "492367" ]
}
