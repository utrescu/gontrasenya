package contrasenya

import (
	"strings"
	"testing"

	"github.com/kless/osutil/user/crypt/sha512_crypt"
)

const PATATA = "$6$hJFtcavV$OSEDo7JuAbTuK2QaXzDiJrXaqx9R8fDV9LYjoCuR9M9o9dfFXOcuQSFYrv8RmHgRZZ1A2B9a.2qkHD4WRLc.z."

func TestComprovaUsuariAmbHashIncorrecteFalla(t *testing.T) {
	usuari := Usuari{"Pere", "x"}
	c := sha512_crypt.New()
	contra, err := comprova(c, usuari, "patata")
	if err == nil {
		t.Error("No hauria de retornar valors", contra)
	}
	if contra == true {
		t.Error("Hauria de tornar 'false'")
	}
}

func TestComprovaAmbContrasenyaIncorrectaFalla(t *testing.T) {
	usuari := Usuari{"Pere", "$6$aaaaaaaaaaa"}
	c := sha512_crypt.New()
	contra, err := comprova(c, usuari, "patata")
	if err == nil {
		t.Error("Hauria de tornar 'false'", contra)
	}

	if contra == true {
		t.Error("Hauria de dir que no ha trobat la contrasenya")
	}

	if strings.HasPrefix(err.Error(), "No correcta") == false {
		t.Error("L'error hauria de començar amb 'No correcta'  i diu '" + err.Error() + "'")
	}
}

func TestComprovaUsuariCorrecte(t *testing.T) {
	usuari := Usuari{"pepet", PATATA}
	c := sha512_crypt.New()
	contra, err := comprova(c, usuari, "patata")
	if err != nil {
		t.Error("No hauria de donar erro quan la contrasenya és correcta")
	}

	if contra == false {
		t.Error("Hauria de dir que ha trobat la contrasenya")
	}
}

func TestComprovaDiversesContrasenyesIElsResultats(t *testing.T) {
	var tests = []struct {
		contrasenya string
		esperat     bool
	}{
		{"", false},
		{"patata", true},
		{"foo", false},
		{"foo", false},
		{"patata2", false},
	}
	usuari := Usuari{"pepet", PATATA}
	c := sha512_crypt.New()
	for _, test := range tests {
		actual, _ := comprova(c, usuari, test.contrasenya)
		if actual != test.esperat {
			t.Errorf("usuari(pepet,%q) = %v; want %v", test.contrasenya, actual, test.esperat)
		}

	}
}

func TestComprovaContrasenyesSenseFitxer(t *testing.T) {
	fitxer := "test.txt"
	user := Usuari{"pere", "NoImporta"}

	resultat, err := ComprovaUsuari(user, fitxer)

	if err == nil {
		t.Error("Hauria de donar error i dóna " + resultat)
	}

	if !strings.HasSuffix(err.Error(), "no such file or directory") {
		t.Error("Hauria de donar que no troba el fitxer")
	}
}

// --- Carregar el fitxer ---

func TestSiCarregaUnUsuariShadowCorrecte(t *testing.T) {
	var tests = []struct {
		linia        string
		esperaUsuari string
		esperaHash   string
	}{
		{"pere:$6$xxxxx$x", "pere", "$6$xxxxx$x"},
		{"pere:$6$xxxxxx", "", ""},
		{"pau:$6$yyyy$y", "pau", "$6$yyyy$y"},
		{"pere:$5$xxxx$x", "", ""},
		{"pere:xxxxxx", "", ""},
		{"pere:$6xxxxxx$xx", "", ""},
		{"patata", "", ""},
	}
	for _, test := range tests {
		user, pass, _ := comprovaLiniaShadow(test.linia)
		if test.esperaUsuari != user || test.esperaHash != pass {
			t.Errorf("Shadow(%q) = %q, %q; want %q, %q", test.linia, user, pass, test.esperaUsuari, test.esperaHash)
		}
	}
}
