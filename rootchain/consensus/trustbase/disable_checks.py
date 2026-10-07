#!/usr/bin/env python3
"""Disable each history-binding guard of the trust-base store once; its isolated negative must fail. Run from the module root."""
from pathlib import Path
import subprocess

signing=Path('rootchain/consensus/trustbase/signing.go')
verified=Path('rootchain/consensus/trustbase/verified_v2.go')
orig={signing:signing.read_text(),verified:verified.read_text()}
cases=[
 (signing,'bind_nil','if a == nil {\n\t\treturn fmt.Errorf("%w: no authority"','if false {\n\t\treturn fmt.Errorf("%w: no authority"','^TestBindingRefusals$','TestBindingRefusals'),
 (signing,'bind_inmemory','len(s.signing.byEpoch) != 0','false','^TestBindingRefusals$','TestBindingRefusals'),
 (signing,'bind_other','s.signing.authority != nil && !sameAuthority(s.signing.authority, a)','false','^TestBindingRefusals$','TestBindingRefusals'),
 (signing,'bind_comparable','reflect.TypeOf(a).Comparable() && ','reflect.TypeOf(a) != nil && ','^TestBindingRefusals$','TestBindingRefusals'),
 (signing,'activate_refused','if s.signing.authority != nil {\n\t\treturn fmt.Errorf("%w: the store takes its configurations','if false {\n\t\treturn fmt.Errorf("%w: the store takes its configurations','^TestABoundStoreRefusesTheInMemoryActivationSeam$','TestABoundStoreRefusesTheInMemoryActivationSeam'),
 (signing,'config_from_authority','if a := s.signing.authority; a != nil {','if a := s.signing.authority; a != nil && false {','^TestABoundStoreTakesEveryConfigurationFromTheHistory$','TestABoundStoreTakesEveryConfigurationFromTheHistory'),
 (signing,'authority_network','if cfg.Network != uint64(tb.NetworkID) {\n\t\t\treturn votesig.Config{}, fmt.Errorf("%w: epoch %d: history network','if false {\n\t\t\treturn votesig.Config{}, fmt.Errorf("%w: epoch %d: history network','^TestABoundStoreRefusesAConfigurationOfAnotherNetwork$','TestABoundStoreRefusesAConfigurationOfAnotherNetwork'),
 (verified,'install_needs_authority','if authority == nil {','if false {','^TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration$/^an_unbound_store$','TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration/an_unbound_store'),
 (verified,'install_exact_config','want != cfg || ','(want != cfg && false) || ','^TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration$/^another_configuration_than_the_history','TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration/another_configuration_than_the_history'),
 (verified,'install_network','|| cfg.Network != uint64(projected.NetworkID)','','^TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration$/^a_configuration_of_another_network','TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration/a_configuration_of_another_network'),
 (verified,'install_nil','if projected == nil {\n\t\treturn nil, errors.New("invalid successor projection")\n\t}\n\ts.mu.RLock()','if false {\n\t\treturn nil, errors.New("invalid successor projection")\n\t}\n\ts.mu.RLock()','^TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration$/^nil$','TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration/nil'),
]
try:
 for path,name,needle,replacement,selector,marker in cases:
  text=orig[path]
  if text.count(needle)!=1:raise SystemExit(f'{name}: check not unique ({text.count(needle)})')
  path.write_text(text.replace(needle,replacement))
  result=subprocess.run(['go','test','./rootchain/consensus/trustbase','-run',selector,'-count=1'],capture_output=True,text=True)
  if result.returncode==0 or f'--- FAIL: {marker}' not in result.stdout:
   raise SystemExit(f'{name}: matching test did not fail\n{result.stdout}\n{result.stderr}')
  print(f'{name}: matching negative failed')
  path.write_text(text)
finally:
 for path,text in orig.items():path.write_text(text)
