#!/bin/sh
wg set wg0 peer $CLIENT_PUBKEY allowed-ips $CLIENT_IP/32
