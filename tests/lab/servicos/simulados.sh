#!/usr/bin/env bash
# Simuladores (Python puro) - SIMULADO, nao e o software real. Ver simuladores/*.py.

_sim() {  # id arquivo
  lab_daemon "$1" "$(env_bin core)/python" "$LAB_DIR/simuladores/$2"
}
start_sim_rdp()     { _sim sim-rdp sim_rdp.py; }
start_sim_mssql()   { _sim sim-mssql sim_mssql.py; }
start_sim_vnc()     { _sim sim-vnc sim_vnc.py; }
start_sim_docker()  { _sim sim-docker sim_docker.py; }
start_sim_k8s()     { _sim sim-k8s sim_k8s.py; }
start_sim_telnet()  { _sim sim-telnet sim_telnet.py; }
start_sim_smtp()    { _sim sim-smtp sim_smtp.py; }
start_sim_elastic() { _sim sim-elastic sim_elastic.py; }
start_sim_winrm()   { _sim sim-winrm sim_winrm.py; }
start_sim_banners() { _sim sim-banners banners.py; }
