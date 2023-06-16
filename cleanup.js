import { getState } from '@actions/core';

var pid = getState("pidToKill");

process.kill(pid);