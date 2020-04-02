#!/usr/bin/env python3

__author__ = 'Alexis Rodriguez'
__email__ = 'rodriguez10011999@gmail.com'

"""
Sources used for scoring descriptions:
  - CompTIA CySa+ Study Guide by Mike Chapple and David Seidl
  - https://www.first.org/cvss/specification-document
"""

try:
  from sys import argv, exit
  from os import _exit
except ImportError as err:
  print(f"Import Error: {err}")

# ------------------------------------------------------------- #
#                       Base Metrics                            #
accessVector = {
  'L': 'Local (L): The attacker must have physical or logical access to the affected system.',
  'A': 'Adjacent Network (A): The attacker must have access to the local network that the affected system is connected to.',
  'N': 'Network (N): The attacker can remote exploit the vulnerability.'
}

accessComplexitiy = {
  'L': 'Low (L): Exploiting the vulnerability does not require specilized conditions.',
  'M': 'Medium (M): Exploiting the vulnerability requires "somewhat specilized" conditions.',
  'H': 'High (H): Exploiting the vulnerability requires "specialized" conditions that would be difficult to find.'
}

# ------------------------------------------------------------- #
#         Base metrics specific to version 3 CVSS scores        #
privilegesRequired = {
  'N': 'None (N): The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.',
  'L': 'Low (L): The attacker requires privileges that provide basic user capabilites that could normally affect only settings and files ownwed by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.',
  'H': 'High (H): The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.'
}

userInteraction = {
  'N': 'None (N): The vulnerable system can be exploited without interaction from any user.',
  'R': 'Required (R): Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.'
}

scope = {
  'U': 'Unchanged (U): An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.',
  'C': 'Changed (C): An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.'
}
# ------------------------------------------------------------- #

authentication = {
  'N': 'None (N): Attackers do not need to authenticate to exploit the vulnerability.',
  'S': 'Single (S): Attackers would need to authenticate once to exploit the vulnerability.',
  'M': 'Multiple (M): Attackers would need to authenticate two or more times exploit the vulnerability.'
}

# ------------------------------------------------------------- #
#                       Impact Metrics                          #
confidentiality = {
  'N': 'None (N): There is no confidentiality impact.',
  'P': 'Partial (P): Access to some information is possible, but the attacker does not have control over what information is compromised.',
  'C': 'Complete (C): All information on the system is compromised.'
}

integrity = {
  'N': 'None (N): There is no integrity impact.',
  'P': 'Partial (P): Modification of some information is possible, but the attacker does not have control over what information is modified.',
  'C': 'Complete (C): The integrity of the system is totally compromised, and the attacker may change any information at will.'
}

availability = {
  'N': 'None (N): There is no availablity impact.',
  'P': 'Partial (P): The performance of the system is degraded.',
  'C': 'Complete (C): The system is completely shut down.'
}

class CVSS2:
  """
  CVSS version 2 class definition.
  """
  def __init__(self, score):
    self.score = score

  def parseScore():
    scoreList = self.score[6:].split('/')
  
class CVSS3:
  """
  CVSS version 3 class definition.
  """
  def __init__(self, score):
    self.score = score

  def parseScore():
    scoreList = self.score[6:].split('/')

def main():
  if len(argv) == 1 or len(argv) > 2:
    print("\033[31mUsage: cvss.py [CVSS Score]\033[0m")
    exit(1)

  cvssScore = argv[1]
  if '2' in cvssScore[:6]:
    instance = CVSS2(cvssScore)
  else:
    instance = CVSS3(cvssScore)

  instance.parseScore()

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    try:
      exit(1)
    except SystemExit:
      _exit(1)
