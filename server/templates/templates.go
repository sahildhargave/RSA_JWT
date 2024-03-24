package templates

// The below code fragment can be found in:

import (
	"log"
	"net/http"
	"html/template"
)

type LoginPage struct{
	BAlertUser  bool
	AlertMsg    string 
}

type RegisterPage struct{
	BAlertUser   bool
	AlertMsg     string 
}

type RestrictedPage struct{
	CsrfSecret  string
	SecretMessage string
}

var templates = template.Must(template.ParseFiles("./server/templates/Files/login.tmpl", "./server/templates/Files/register.tmpl", "./server/templates/Files/restricted.tmpl"))


func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}){
	err := templates.ExecuteTemplate(w , tmpl+".tmpl", p)
	if err != nil{
		log.Printf("Template error here: %v%", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}