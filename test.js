const { expect } = require('chai');
const { getResponse } = require('./server');

describe('getResponse', () => {
    it('should return a response from API', async () => {
        const response = await getResponse('Test input');
        expect(response).to.be.a('string'); // test llojin e pergjigjes
        expect(response).to.not.be.empty; // test se pegjigjda nuk eshte null
    });
});



// ofline mode