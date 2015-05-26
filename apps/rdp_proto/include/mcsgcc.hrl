%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-record(mcs_ci, {data, calling=[1], called=[1], max_channels=34, max_users=2, max_tokens=0, num_priorities=1, min_throughput=0, max_height=1, max_size=65535, version=2, conf_name=""}).

-record(mcs_cr, {data, called=0, max_channels=34, max_users=2, max_tokens=0, num_priorities=1, min_throughput=0, max_height=1, max_size=65535, version=2, mcs_result = 'rt-successful', node=1001, tag=1, result=success}).

-record(mcs_edr, {height=0, interval=0}).
-record(mcs_aur, {}).
-record(mcs_auc, {status='rt-successful', user}).
-record(mcs_cjr, {channel, user}).
-record(mcs_cjc, {channel, status='rt-successful', user}).
-record(mcs_tir, {user, token}).
-record(mcs_tic, {user, token, status='rt-successful', token_status='notInUse'}).
-record(mcs_data, {user, channel, priority=high, data}).
-record(mcs_srv_data, {user, channel, priority=high, data}).
-record(mcs_dpu, {reason='rn-user-requested'}).
