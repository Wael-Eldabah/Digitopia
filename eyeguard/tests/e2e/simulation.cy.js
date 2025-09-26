// Software-only simulation / demo — no real systems will be contacted or modified.
describe('Simulation Flow', () => {
  it('launches dashboard and navigates to simulation', () => {
    cy.visit('http://localhost:5173/');
    cy.contains('Simulation').click();
    cy.url().should('include', '/simulation');
    cy.get('form').within(() => {
      cy.get('input[name="ip_address"]').clear().type('198.51.100.42');
      cy.get('input[name="hostname"]').clear().type('training-sim');
      cy.root().submit();
    });
    cy.contains('Simulation Terminal').should('exist');
  });
});
