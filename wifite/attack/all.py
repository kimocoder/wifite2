#!/usr/bin/env python
# -*- coding: utf-8 -*-

from enum import Enum
from .pmkid import AttackPMKID
from .wep import AttackWEP
from .wpa import AttackWPA
from .wps import AttackWPS
from ..config import Configuration
from ..model.target import WPSState
from ..util.color import Color

class Answer(Enum):
    Skip = 1
    ExitOrReturn = 2
    Continue = 3
    Ignore = 4

class AttackAll(object):
    @classmethod
    def attack_multiple(cls, targets):
        """
        Attacks all given `targets` (list[wifite.model.target]) until user interruption.
        Returns: Number of targets that were attacked (int)
        """
        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            # Warn that WPS attacks are not available.
            Color.pl('{!} {O}Note: WPS attacks are not possible because you do not have {C}reaver{O} nor {C}bully{W}')

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            if Configuration.attack_max != 0 and index > Configuration.attack_max:
                print(("Attacked %d targets, stopping because of the --first flag" % Configuration.attack_max))
                break
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else '{O}ESSID unknown{W}'

            Color.pl('\n{+} ({G}%d{W}/{G}%d{W})'
                     % (index, len(targets)) + ' Starting attacks against {C}%s{W} ({C}%s{W})' % (bssid, essid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        """
        Attacks a single `target` (wifite.model.target).
        Returns: True if attacks should continue, False otherwise.
        """
        global attack
        if 'MGT' in target.authentication:
            Color.pl("\n{!}{O}Skipping. Target is using {C}WPA-Enterprise {O}and can not be cracked.")
            return True

        attacks = []

        if Configuration.use_eviltwin:
            # TODO: EvilTwin attack
            pass

        elif target.primary_encryption == 'WEP':
            attacks.append(AttackWEP(target))

        elif target.primary_encryption.startswith('WPA'): # Covers WPA, WPA2, WPA3
            # WPA can have multiple attack vectors:

            # WPS
            # For WPA3, WPS is not applicable in the same way.
            # WPS is generally being phased out with WPA3, though some transition modes might exist.
            # We will only attempt WPS if it's explicitly WPA or WPA2 (not WPA3).
            if target.primary_encryption != 'WPA3' and \
               not Configuration.use_pmkid_only and \
               target.wps is WPSState.UNLOCKED and \
               AttackWPS.can_attack_wps():

                # Pixie-Dust
                if Configuration.wps_pixie:
                    attacks.append(AttackWPS(target, pixie_dust=True))

                # Null PIN zero-day attack
                if Configuration.wps_pin: # This implies not wps_pixie_only
                    attacks.append(AttackWPS(target, pixie_dust=False, null_pin=True))

                # PIN attack
                if Configuration.wps_pin: # This implies not wps_pixie_only
                    attacks.append(AttackWPS(target, pixie_dust=False))

            # PMKID and Handshake attacks are applicable to WPA, WPA2, and WPA3
            if not Configuration.wps_only: # If --wps-only is not set
                # PMKID
                if not Configuration.dont_use_pmkid: # If --no-pmkid is not set
                    attacks.append(AttackPMKID(target))

                # Handshake capture
                if not Configuration.use_pmkid_only: # If --pmkid (means pmkid-only) is not set
                    attacks.append(AttackWPA(target))
            elif target.primary_encryption == 'WPA3' and Configuration.wps_only:
                # Special case: If it's WPA3 and --wps-only is specified,
                # WPS attacks are skipped. We should still allow PMKID/Handshake for WPA3.
                Color.pl('{!} {O}Note: --wps-only is active, but target is WPA3. WPS attacks are not applicable.')
                Color.pl('{+} {C}Proceeding with PMKID and Handshake attacks for WPA3 target.{W}')
                if not Configuration.dont_use_pmkid:
                    attacks.append(AttackPMKID(target))
                if not Configuration.use_pmkid_only:
                    attacks.append(AttackWPA(target))


        if not attacks:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
            return True  # Keep attacking other targets (skip)

        while attacks:
            # Needed by infinite attack mode in order to count how many targets were attacked
            target.attacked = True
            attack = attacks.pop(0)
            try:
                result = attack.run()
                if result:
                    break  # Attack was successful, stop other attacks.
            except Exception as e:
                # TODO:kimocoder: below is a great way to handle Exception
                # rather then running full traceback in run of parsing to console.
                Color.pl('\r {!} {R}Error{W}: %s' % str(e))
                #Color.pexception(e)         # This was the original one which parses full traceback
                #Color.pl('\n{!} {R}Exiting{W}\n')      # Another great one for other uasages.
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Interrupted{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer == Answer.Continue:
                    continue  # Keep attacking the same target (continue)
                elif answer == Answer.Skip:
                    return True  # Keep attacking other targets (skip)
                elif answer == Answer.Ignore:
                    from ..model.result import CrackResult
                    CrackResult.ignore_target(target)
                    return True  # Ignore current target and keep attacking other targets (ignore)
                else:
                    return False  # Stop all attacks (exit)

        if attack.success:
            attack.crack_result.save()

        return True  # Keep attacking other targets

    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        """
        Asks user if attacks should continue onto other targets
        Returns:
            Answer.Skip if the user wants to skip the current target
            Answer.Ignore if the user wants to ignore the current target
            Answer.Continue if the user wants to continue to the next attack on the current target
            Answer.ExitOrReturn if the user wants to stop the remaining attacks
        """
        if attacks_remaining == 0 and targets_remaining == 0:
            return  # No targets or attacksleft, drop out

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        prompt = ' and '.join(prompt_list) + ' remain'
        Color.pl('{+} %s' % prompt)

        prompt = '{+} Do you want to'
        options = '('

        if attacks_remaining > 0:
            prompt += ' {G}continue{W} attacking,'
            options += '{G}c{W}{D}, {W}'

        if targets_remaining > 0:
            prompt += ' {O}skip{W} to the next target,'
            options += '{O}s{W}{D}, {W}'

        prompt += ' skip and {P}ignore{W} current target,'
        options += '{P}i{W}{D}, {W}'

        if Configuration.infinite_mode:
            options += '{R}r{W})'
            prompt += ' or {R}return{W} to scanning %s? {C}' % options
        else:
            options += '{R}e{W})'
            prompt += ' or {R}exit{W} %s? {C}' % options

        Color.p(prompt)
        answer = input().lower()

        if answer.startswith('s'):
            return Answer.Skip
        elif answer.startswith('e') or answer.startswith('r'):
            return Answer.ExitOrReturn  # Exit/Return
        elif answer.startswith('i'):
            return Answer.Ignore  # Ignore
        else:
            return Answer.Continue  # Continue
