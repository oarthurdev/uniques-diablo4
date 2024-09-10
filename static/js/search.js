document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search');
    const suggestionsContainer = document.getElementById('suggestions');

    searchInput.addEventListener('input', async () => {
        const query = searchInput.value.trim();
        if (query.length === 0) {
            suggestionsContainer.innerHTML = '';
            return;
        }

        try {
            const response = await fetch(`/search_suggestions?q=${encodeURIComponent(query)}`);
            const suggestions = await response.json();

            // Garante que o suggestionsContainer é limpo antes de adicionar novas sugestões
            if (Array.isArray(suggestions)) {
                suggestionsContainer.innerHTML = suggestions.map(item => {
                    if (item) {
                        return `<div data-name="${item}">${item}</div>`;
                    } else {
                        console.error('Item inválido:', item); // Verifique itens inválidos
                        return '';
                    }
                }).join('');
            } else {
                console.error('Dados de sugestões inesperados:', suggestions);
            }
        } catch (error) {
            console.error('Erro ao buscar sugestões:', error);
        }
    });

    suggestionsContainer.addEventListener('click', (event) => {
        if (event.target.tagName === 'DIV') {
            // Preenche o campo de busca com a sugestão selecionada
            searchInput.value = event.target.getAttribute('data-name');
            // Limpa o container de sugestões
            suggestionsContainer.innerHTML = '';
            // Aplica o filtro com base na sugestão selecionada
            applyFilters();
        }
    });

    document.addEventListener('click', (event) => {
        if (!event.target.closest('.search-container')) {
            suggestionsContainer.innerHTML = '';
        }
    });

    function applyFilters() {
        // Obtém o valor atual do campo de busca
        const nameFilter = searchInput.value.trim().toLowerCase();
        const selectedClass = document.getElementById('classFilter').value.toLowerCase();
        const uniques = document.querySelectorAll('#uniquesContainer .item');

        let filteredItems = 0;

        uniques.forEach(function(card) {
            const itemName = card.getAttribute('data-name').toLowerCase();
            const itemClass = card.getAttribute('data-class').toLowerCase();
            let showCard = true;

            if (selectedClass && itemClass.indexOf(selectedClass) === -1) {
                showCard = false;
            }

            if (nameFilter && !itemName.includes(nameFilter)) {
                showCard = false;
            }

            card.style.display = showCard ? 'block' : 'none';
            if (showCard) filteredItems++;
        });

        // Atualiza a paginação com base no número total de itens filtrados
        const totalPages = Math.ceil(filteredItems / ITEMS_PER_PAGE);
        updatePagination(totalPages);
    }
});