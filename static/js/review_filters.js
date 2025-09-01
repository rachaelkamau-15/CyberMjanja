document.addEventListener('DOMContentLoaded', function() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const questionCards = document.querySelectorAll('.question-card');

    if (!filterButtons.length || !questionCards.length) {
        return; // Do nothing if elements aren't on the page
    }

    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Update active state on buttons
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');

            const filter = this.getAttribute('data-filter');

            // Show/hide cards based on the selected filter
            questionCards.forEach(card => {
                const cardStatus = card.getAttribute('data-status');
                const isBookmarked = card.getAttribute('data-bookmarked') === 'true';
                let showCard = false;

                switch (filter) {
                    case 'all':
                        showCard = true;
                        break;
                    case 'correct':
                        showCard = (cardStatus === 'correct');
                        break;
                    case 'incorrect':
                        showCard = (cardStatus === 'incorrect');
                        break;
                    case 'bookmarked':
                        showCard = isBookmarked;
                        break;
                }

                card.style.display = showCard ? 'block' : 'none';
            });
        });
    });

    // Collapse/Expand all functionality
    const collapseToggle = document.getElementById('collapse-toggle');
    if (collapseToggle) {
        collapseToggle.addEventListener('click', function(e) {
            e.preventDefault();
            const questionBodies = document.querySelectorAll('.question-body');
            // Check the current text to determine the action
            const isCollapsing = this.textContent.trim() === 'Collapse all';

            questionBodies.forEach(body => {
                // We use a class to toggle visibility to allow for CSS transitions if desired
                if (isCollapsing) {
                    body.style.display = 'none';
                } else {
                    body.style.display = 'block';
                }
            });

            this.textContent = isCollapsing ? 'Expand all' : 'Collapse all';
        });
    }
});