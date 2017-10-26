package contrasenya

import (
	"bufio"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/kless/osutil/user/crypt"
	"github.com/kless/osutil/user/crypt/sha512_crypt"
)

/*
  Usuari emmagatzema les contrasenyes de cada un dels usuaris
*/
type Usuari struct {
	nom  string
	hash string
}

func init() {

}

/*
Comprova si una línia de 'shadow' és correcta o no

@return usuari i hash o bé error
*/
func comprovaLiniaShadow(linia string) (string, string, error) {
	if strings.Count(linia, ":") == 0 {
		return "", "", errors.New("No té ':'")
	}
	var separa = strings.Split(linia, ":")
	if strings.HasPrefix(separa[1], "$6$") && strings.Count(separa[1], "$") == 3 {
		return separa[0], separa[1], nil
	}
	return "", "", errors.New("No és correcte '$'")
}

/*
ObtenirElsusuariDeShadow serveix per obtenir una llista
amb els usuaris i contrasenya en una estructrua d'element
'usuari' a partir d'un fitxer en format shadow

@returns llista dels usuaris
*/
func ObtenirElsusuariDeShadow(nomFitxer string) []Usuari {
	var llista []Usuari
	file, err := os.Open(nomFitxer)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var linia = scanner.Text()
		nom, hash, err := comprovaLiniaShadow(linia)
		if err == nil {
			llista = append(llista, Usuari{nom, hash})
		}
	}
	return llista
}

/*
Comprova si la contrasenya de l'Usuari és la que diu o no

@returns si l'ha trobat i si hi ha hagut un error
*/
func comprova(c crypt.Crypter, user Usuari, paraula string) (resultat bool, err error) {
	salt := user.hash
	hashResultat, err := c.Generate([]byte(paraula), []byte(salt))
	if err != nil {
		return false, err
	}
	// Mirem si hem trobat l'error
	if hashResultat == user.hash {
		return true, nil
	}
	return false, errors.New("No correcta " + paraula)
}

/*
ComprovaUsuari comprova si la contrasenya d'un Usuari està entre les del
fitxer de contrasenyes que es proporciona en el paràmetre
diccionari

@returns a contrasenya hi haurà la contrasenya trobada o err en cas
d'error o que no s'hagi trobat
*/
func ComprovaUsuari(user Usuari, diccionari string) (resultat string, err error) {

	file, err := os.Open(diccionari)
	if err != nil {
		return "", err
	}

	defer file.Close()
	c := sha512_crypt.New()
	scanner := bufio.NewScanner(file)
	// compta := 0
	for scanner.Scan() {
		var paraula = scanner.Text()
		// fmt.Println("Provant l'Usuari " + user.nom + ":" + paraula)
		resultat, _ := comprova(c, user, paraula)

		if resultat == true {
			return user.nom + ":" + paraula, nil
		}

		// compta = (compta + 1)
		// if compta%4000 == 0 {
		// 	fmt.Println(compta, " ... provant "+paraula)
		// }
	}
	return "", errors.New(user.nom + ": contrasenya no trobada")
}
