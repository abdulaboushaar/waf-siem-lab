# Paranoia sweep summary


For my login page I chose PL1, since the WAF does nothing against brute force attacks. Brute force is the real threat on the login page, and the SIEM is what actually blocks it.
For my search page, PL2 is the best choice. Going from PL2 to PL3 catches only one more attack but doubles the false positive rate, so it does not make sense to run at PL3. Instead of doubling the FP rate, I would introduce an app fix: because the WAF is a compensating control, the real fix is parameterizing the search.php query, after which SQLi cannot reach the database regardless of PL. The WAF alone never fully closes the attack surface, which you can see at PL3, where 12 attacks still made it through.
For my product pages I chose PL1, since a product page has almost no attack surface and nothing to false-positive on, so the PL barely matters. What really matters here is the real XSS defense, which is output encoding in the app when it renders comments.
On PL1 72.5% of SQLI attacks were blocked On PL2 82.5% of SQLI attacks were blocked. On PL3 85% of SQLI attacks were blocked. PL4 had the same attack block percentages as PL3 but it increased the FP to 70%. On all paranoia levels, the traversal block rate was 100% and the XSS block rate stayed consistent at 66.7%. Looking at all this data we can tell that most of the leaking 18% of attacks are coming from XSS attacks. We can also conclude that only SQLI responded to paranoia. 


| PL | Attacks blocked | Attacks reached app | SQLi errored DB | Benign blocked | FP rate |
|----|-----------------|---------------------|-----------------|----------------|--------:|
| 1 | 69/90 (76.7%) | 17 | 2 | 4/100 | 4.0% |
| 2 | 73/90 (81.1%) | 13 | 1 | 9/100 | 9.0% |
| 3 | 74/90 (82.2%) | 12 | 0 | 19/100 | 19.0% |
| 4 | 74/90 (82.2%) | 12 | 0 | 70/100 | 70.0% |

Attacks blocked and benign blocked come from the HTTP response the WAF returned (403). Attacks reached app and SQLi errored DB come from the app log, joined on request_id. FP rate is benign blocked over benign sent.
