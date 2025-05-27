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
    
    // New code for expandable skills
    const expandableSkills = document.querySelectorAll('.skill-tag.expandable');
    
    expandableSkills.forEach(skill => {
        skill.addEventListener('click', function() {
            const skillId = this.getAttribute('data-skill');
            const detailsElement = document.getElementById(`${skillId}-details`);
            
            // Remove active class from all skill tags
            document.querySelectorAll('.skill-tag.expandable').forEach(el => {
                el.classList.remove('active');
            });
            
            // Close all other open skill details
            document.querySelectorAll('.skill-details.active').forEach(el => {
                if (el.id !== `${skillId}-details`) {
                    el.classList.remove('active');
                }
            });
            
            // Load skill content if needed
            loadSkillContent(skillId);
            
            // Toggle this skill detail
            detailsElement.classList.toggle('active');
            
            // Add active class to this skill tag if the details are shown
            if (detailsElement.classList.contains('active')) {
                this.classList.add('active');
                
                // Scroll to the skill detail
                setTimeout(() => {
                    detailsElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }, 100);
            }
        });
    });
    
    // Close buttons for skill details - FIXED to also remove active class from skill tag
    document.querySelectorAll('.close-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const detailsElement = this.closest('.skill-details');
            const skillId = detailsElement.id.replace('-details', '');
            const skillTag = document.querySelector(`.skill-tag[data-skill="${skillId}"]`);
            
            // Remove active class from skill tag
            if (skillTag) {
                skillTag.classList.remove('active');
            }
            
            // Close the details
            detailsElement.classList.remove('active');
        });
    });
    
    // Function to escape HTML for code examples
    function escapeHTML(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Process all code blocks to ensure HTML is escaped
    document.querySelectorAll('pre code').forEach(codeBlock => {
        // Get the text content
        const originalCode = codeBlock.textContent;
        
        // Escape any HTML in the code
        codeBlock.textContent = originalCode;
    });
    
    // UPDATED: Changed highlightBlock to highlightElement to fix deprecation warning
    if (typeof hljs !== 'undefined') {
        document.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
        });
    }
    
    // Safely handle JSX examples (which contain HTML-like syntax)
    function safelyLoadCodeExamples() {
        // Find all JSX examples which might contain problematic syntax
        document.querySelectorAll('code.language-jsx').forEach(codeBlock => {
            // Replace angle brackets with HTML entities in the actual HTML
            const content = codeBlock.innerHTML;
            const safeContent = content
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
                
            // Set the safe content back
            codeBlock.innerHTML = safeContent;
        });
        
        // Re-apply highlighting if it got messed up
        // UPDATED: Changed highlightBlock to highlightElement to fix deprecation warning
        if (typeof hljs !== 'undefined') {
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        }
    }
    
    // Call this function after the page has loaded
    window.addEventListener('load', safelyLoadCodeExamples);
});

// Add this function to your existing script
async function loadSkillContent(skillId) {
    const detailsElement = document.getElementById(`${skillId}-details`);
    
    // Don't load if already loaded
    if (detailsElement.dataset.loaded === "true") {
        return;
    }
    
    try {
        const response = await fetch(`skills/${skillId}.html`);
        if (!response.ok) {
            throw new Error(`Failed to load skill content (${response.status})`);
        }
        
        const content = await response.text();
        detailsElement.innerHTML = content;
        detailsElement.dataset.loaded = "true";
        
        // Apply syntax highlighting to any code blocks
        if (typeof hljs !== 'undefined') {
            detailsElement.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        }
        
        // Add event listener to the close button
        const closeBtn = detailsElement.querySelector('.close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', function() {
                const skillTag = document.querySelector(`.skill-tag[data-skill="${skillId}"]`);
                
                // Remove active class from skill tag
                if (skillTag) {
                    skillTag.classList.remove('active');
                }
                
                // Close the details
                detailsElement.classList.remove('active');
            });
        }
    } catch (error) {
        console.error(`Error loading skill content for ${skillId}:`, error);
        detailsElement.innerHTML = `
            <div class="skill-details-header">
                <h4>Error Loading Content</h4>
                <button class="close-btn"><i class="fas fa-times"></i></button>
            </div>
            <div class="skill-details-content">
                <p>Sorry, we couldn't load the content for this skill. Please try again later.</p>
            </div>
        `;
    }
}
