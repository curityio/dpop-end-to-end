const allOrders = [
    {
        customerId: '101',
        productId: 'AB3546',
        amountUSD: 20000,
    },
    {
        customerId: '102',
        productId: 'XM0922',
        amountUSD: 30000,
    },
    {
        customerId: '103',
        productId: 'PL9771',
        amountUSD: 50000,
    },
    {
        customerId: '102',
        productId: 'LK9834',
        amountUSD: 45000,
    },
    {
        customerId: '101',
        productId: 'NG2079',
        amountUSD: 60000,
    }
]

export function getOrders(customerId: string) {
    return allOrders.filter(o => o.customerId === customerId)
}
