document.addEventListener("DOMContentLoaded", () => {
    // Add tooltips to course tags
    const courseTags = document.querySelectorAll('.course-tag');
    
    courseTags.forEach(tag => {
        const description = tag.getAttribute('data-description');
        if (description) {
            const tooltip = document.createElement('span');
            tooltip.className = 'tooltip';
            tooltip.textContent = description;
            tag.appendChild(tooltip);
            
            // For mobile: tap to show/hide tooltip
            tag.addEventListener('click', function(e) {
                // Toggle a class to show the tooltip on mobile
                if (window.innerWidth <= 768) {
                    const allTags = document.querySelectorAll('.course-tag');
                    allTags.forEach(t => {
                        if (t !== this) t.classList.remove('mobile-tooltip-active');
                    });
                    this.classList.toggle('mobile-tooltip-active');
                    e.stopPropagation();
                }
            });
        }
    });
    
    // Hide tooltips when clicking elsewhere
    document.addEventListener('click', function() {
        document.querySelectorAll('.mobile-tooltip-active').forEach(tag => {
            tag.classList.remove('mobile-tooltip-active');
        });
    });
});
