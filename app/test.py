from securite import MaskRequest
from pydantic import ValidationError
def test_maskrequest_identical_numbers():
    try:
        # Créez une instance avec caller_real et callee_real identiques
        mask_request = MaskRequest(caller_real="+21612345678", callee_real="+21612345678")
        print("Test échoué : aucune erreur levée pour numéros identiques")
    except ValidationError as e:
        # Affichez l'erreur levée par Pydantic (attendue)
        print("Test réussi : ValidationError levée")
        print(e)

if __name__ == "__main__":
    test_maskrequest_identical_numbers()