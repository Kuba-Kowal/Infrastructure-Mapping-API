const view_button = document.getElementById('view_btn')
const scan_button = document.getElementById('scan_btn')
const input = document.getElementById('domain_input')
const results = document.getElementById('results')

function addText(card, text){
    const element = document.createElement("p")
    element.textContent = text
    card.appendChild(element)
}

function outputNodes(data){}

function outputRelationships(data){
    Object.values(data).forEach(row => {
                const card_frame = document.createElement("div")
                const card_title = document.createElement("summary")
                const card = document.createElement("details")
                const source_element = document.createElement("h3")
                
                card_frame.appendChild(card)
                card_title.textContent = row.relationship.type
                card.appendChild(card_title)
                

                source_element.textContent = "SOURCE"
                card.appendChild(source_element)

                const source_array = [row.source.data, row.source.type]
                for (const item of source_array) {
                    addText(card, item)
                }

                Object.entries(row.source.properties).forEach(([key, value]) => {
                    const element = document.createElement("p")
                    element.textContent = `${key}: ${value}`
                    card.appendChild(element)
                })

                const target_element = document.createElement("h3")
                target_element.textContent = "TARGET"
                card.appendChild(target_element)

                const target_array = [row.target.data, row.target.type]
                for (const item of target_array) {
                    addText(card, item)
                }

                Object.entries(row.target.properties).forEach(([key, value]) => {
                    const element = document.createElement("p")
                    element.textContent = `${key}: ${value}`
                    card.appendChild(element)
                })

                const relationship_element = document.createElement("h3")
                relationship_element.textContent = "OBSERVED AT"
                card.appendChild(relationship_element)
                addText(card, row.relationship.finished_at)

                const break_element = document.createElement("br")
                card.appendChild(break_element)

                results.appendChild(card)
})}

scan_button.addEventListener("click", async function() {
    const target = input.value;

    const response = await fetch(`http://192.168.0.52:8000/api/v1/scan?domain=${target}`, {method: "POST"})

    console.log(response)
})

view_button.addEventListener("click", async function() {
    const target = input.value;

    await fetch(`http://192.168.0.52:8000/api/v1/view?domain=${target}`)
        .then(response => response.json())
        .then(outputRelationships)
        .catch(error => console.error(error))
})

