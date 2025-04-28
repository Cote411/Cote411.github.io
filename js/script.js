document.addEventListener("DOMContentLoaded", () => {
    const greetingElement = document.createElement("p");
    const hours = new Date().getHours();
    let greeting;

    if (hours < 12) {
        greeting = "Good morning!";
    } else if (hours < 18) {
        greeting = "Good afternoon!";
    } else {
        greeting = "Good evening!";
    }

    greetingElement.textContent = greeting;
    greetingElement.style.fontSize = "1.2rem";
    greetingElement.style.fontWeight = "bold";
    greetingElement.style.textAlign = "center";
    greetingElement.style.marginTop = "1rem";

    document.querySelector("header").appendChild(greetingElement);
});